import express, { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieSession from 'cookie-session';

dotenv.config();

const app = express();

app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://spotifydevapi.arwindpianist.store',
      'http://127.0.0.1:8081',
      'http://localhost:8081',
      'http://127.0.0.1:3000',
      'http://localhost:3000',
      process.env.FRONTEND_URL || ''
    ];
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Use cookie-session for stateless session storage
app.use(cookieSession({
  name: 'session',
  keys: [process.env.SESSION_SECRET || 'supersecretkey'],
  maxAge: 60 * 60 * 1000, // 1 hour
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  domain: process.env.NODE_ENV === 'production' ? '.arwindpianist.store' : undefined,
  httpOnly: true,
}));

// Log environment variables for debugging (do not log secrets in production)
console.log('SESSION_SECRET:', process.env.SESSION_SECRET ? '[set]' : '[not set]');
console.log('SPOTIFY_CLIENT_ID:', process.env.SPOTIFY_CLIENT_ID ? '[set]' : '[not set]');
console.log('SPOTIFY_CLIENT_SECRET:', process.env.SPOTIFY_CLIENT_SECRET ? '[set]' : '[not set]');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('FRONTEND_URL:', process.env.FRONTEND_URL);

// Refresh access token if expired or about to expire
async function refreshAccessToken(req: Request): Promise<void> {
  const session = req.session as Record<string, any>;
  if (!session || !session.refreshToken) throw new Error('No refresh token available');
  const refreshToken = session.refreshToken;

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: process.env.SPOTIFY_CLIENT_ID || '',
    client_secret: process.env.SPOTIFY_CLIENT_SECRET || '',
  });

  const response = await axios.post('https://accounts.spotify.com/api/token', params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  session.accessToken = response.data.access_token;
  if (response.data.refresh_token) {
    session.refreshToken = response.data.refresh_token;
  }
  session.tokenExpiresAt = Date.now() + (response.data.expires_in * 1000);
}

// Middleware to ensure token is valid, refresh if expired
function ensureAuthenticated(req: Request, res: Response, next: NextFunction) {
  const session = req.session as Record<string, any>;
  if (!session || !session.accessToken) {
    res.status(401).json({ error: 'Not authenticated' });
    return;
  }

  // Check token expiry, refresh if within 1 minute of expiry or expired
  if (!session.tokenExpiresAt || Date.now() > session.tokenExpiresAt - 60000) {
    refreshAccessToken(req)
      .then(() => next())
      .catch((error) => {
        console.error('Authentication error:', (error as any).response?.data || (error as Error).message);
        res.status(401).json({ error: 'Access token expired or invalid, please reauthenticate' });
      });
  } else {
    next();
  }
}

// Utility to wrap async route handlers
function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Exchange Authorization Code for Tokens and store in session
app.post('/auth/token', asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { code, redirectUri, clientId, clientSecret } = req.body;

  if (!code || !redirectUri || !clientId || !clientSecret) {
    res.status(400).json({ error: 'Missing required parameters: code, redirectUri, clientId, clientSecret' });
    return;
  }

  try {
    const tokenResponse = await axios.post('https://accounts.spotify.com/api/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const session = req.session as Record<string, any>;
    session.accessToken = tokenResponse.data.access_token;
    session.refreshToken = tokenResponse.data.refresh_token;
    session.tokenExpiresAt = Date.now() + (tokenResponse.data.expires_in * 1000);

    res.json({
      access_token: tokenResponse.data.access_token,
      expires_in: tokenResponse.data.expires_in,
      token_type: tokenResponse.data.token_type,
    });
  } catch (error) {
    console.error('Token exchange failed:', (error as any).response?.data || (error as Error).message);
    res.status(500).json({ error: 'Failed to exchange code for token' });
  }
}));

// Search for artist by name
app.get('/search/artist', ensureAuthenticated, asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { q } = req.query;

  if (!q || typeof q !== 'string') {
    res.status(400).json({ error: 'Missing or invalid query parameter: q' });
    return;
  }

  try {
    const session = req.session as Record<string, any>;
    const accessToken = session.accessToken;
    if (!accessToken) throw new Error('No access token');
    const response = await axios.get('https://api.spotify.com/v1/search', {
      params: {
        q,
        type: 'artist',
        limit: 10,
      },
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const artists = response.data.artists.items.map((artist: any) => ({
      id: artist.id,
      name: artist.name,
      followers: artist.followers.total,
      genres: artist.genres,
      images: artist.images,
      popularity: artist.popularity,
      spotifyUrl: artist.external_urls.spotify,
    }));

    res.json({ artists });
  } catch (error) {
    console.error('Artist search error:', (error as any).response?.data || (error as Error).message);
    if ((error as any).response?.status === 401) {
      res.status(401).json({ error: 'Access token expired or invalid' });
      return;
    }
    res.status(500).json({ error: 'Failed to search artists' });
  }
}));

// Get albums for artist
app.get('/albums/:artistId', ensureAuthenticated, asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { artistId } = req.params;
  if (!artistId) {
    res.status(400).json({ error: 'Missing artistId parameter' });
    return;
  }

  try {
    const session = req.session as Record<string, any>;
    const accessToken = session.accessToken;
    if (!accessToken) throw new Error('No access token');
    const response = await axios.get(`https://api.spotify.com/v1/artists/${artistId}/albums`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      params: {
        include_groups: 'album,single',
        limit: 20,
      },
    });

    const albums = response.data.items.map((album: any) => ({
      id: album.id,
      title: album.name,
      releaseDate: album.release_date,
      totalTracks: album.total_tracks,
      images: album.images,
      spotifyUrl: album.external_urls.spotify,
    }));

    res.json({ albums });
  } catch (error) {
    console.error('Albums fetch error:', (error as any).response?.data || (error as Error).message);
    if ((error as any).response?.status === 401) {
      res.status(401).json({ error: 'Access token expired or invalid' });
      return;
    }
    res.status(500).json({ error: 'Failed to fetch albums' });
  }
}));

// Get tracks for album
app.get('/tracks/:albumId', ensureAuthenticated, asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { albumId } = req.params;
  if (!albumId) {
    res.status(400).json({ error: 'Missing albumId parameter' });
    return;
  }

  try {
    const session = req.session as Record<string, any>;
    const accessToken = session.accessToken;
    if (!accessToken) throw new Error('No access token');
    const response = await axios.get(`https://api.spotify.com/v1/albums/${albumId}/tracks`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      params: {
        limit: 50,
      },
    });

    const tracks = response.data.items.map((track: any) => ({
      id: track.id,
      title: track.name,
      durationMs: track.duration_ms,
      previewUrl: track.preview_url,
      spotifyUrl: track.external_urls.spotify,
      trackNumber: track.track_number,
    }));

    res.json({ tracks });
  } catch (error) {
    console.error('Tracks fetch error:', (error as any).response?.data || (error as Error).message);
    if ((error as any).response?.status === 401) {
      res.status(401).json({ error: 'Access token expired or invalid' });
      return;
    }
    res.status(500).json({ error: 'Failed to fetch tracks' });
  }
}));

// Reset session (clear tokens)
app.post('/auth/reset', (req: Request, res: Response) => {
  // For cookie-session, to clear the session, set req.session = null as any
  (req.session as any) = null;
  res.json({ message: 'Session reset successful' });
});

// Add explicit handler for OPTIONS requests to always return CORS headers
app.options('*', cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://spotifydevapi.arwindpianist.store',
      'http://127.0.0.1:8081',
      'http://localhost:8081',
      'http://127.0.0.1:3000',
      'http://localhost:3000',
      process.env.FRONTEND_URL || ''
    ];
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Add a global error handler for CORS errors and other uncaught errors
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err && err.message === 'Not allowed by CORS') {
    res.status(403).json({ error: 'CORS error: Origin not allowed' });
  } else {
    // For CORS preflight OPTIONS requests, always respond with 204 if error
    if (req.method === 'OPTIONS') {
      res.status(204).send();
    } else {
      res.status(500).json({ error: err?.message || 'Internal server error' });
    }
  }
});

// Export the app for Vercel serverless
export default app;
