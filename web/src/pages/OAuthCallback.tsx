import React from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Box, CircularProgress, Typography, Container, Alert } from '@mui/material';
import { useAuth } from '../context/AuthContext';

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

const OAuthCallback: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { persistAuth } = useAuth();
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    // Tokens are now delivered via HTTP-only cookies (set by the backend)
    const accessToken = getCookie('cbom_access_token');
    const refreshToken = getCookie('cbom_refresh_token');
    const edition = (getCookie('cbom_edition') || 'oss') as 'oss' | 'enterprise';
    const userId = getCookie('cbom_user_id');
    const userName = getCookie('cbom_user_name');
    const userEmail = getCookie('cbom_user_email');
    const userRole = getCookie('cbom_user_role') || 'viewer';

    // Fallback: check URL params (for backward compatibility)
    const urlAccessToken = searchParams.get('access_token');
    const token = accessToken || urlAccessToken;

    if (!token) {
      setError('No access token received from authentication provider. Please try again.');
      return;
    }

    const finish = async () => {
      try {
        if (userId && userName) {
          persistAuth({
            access_token: token,
            refresh_token: refreshToken || searchParams.get('refresh_token'),
            user: { id: userId, name: userName, email: userEmail || '', role: userRole },
            edition,
          });
        } else {
          persistAuth({
            access_token: token,
            refresh_token: refreshToken || searchParams.get('refresh_token'),
            user: { id: 'loading', name: 'Loading...', email: '', role: 'viewer' },
            edition,
          });
        }
        // Clear OAuth cookies (they've served their purpose)
        document.cookie = 'cbom_access_token=; max-age=0; path=/';
        document.cookie = 'cbom_refresh_token=; max-age=0; path=/';
        document.cookie = 'cbom_edition=; max-age=0; path=/';
        document.cookie = 'cbom_user_id=; max-age=0; path=/';
        document.cookie = 'cbom_user_name=; max-age=0; path=/';
        document.cookie = 'cbom_user_email=; max-age=0; path=/';
        document.cookie = 'cbom_user_role=; max-age=0; path=/';

        navigate('/dashboard', { replace: true });
      } catch {
        setError('Failed to complete authentication. Please try logging in manually.');
      }
    };
    finish();
  }, [searchParams, navigate, persistAuth]);

  if (error) {
    return (
      <Container maxWidth="sm" sx={{ mt: 8 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="sm" sx={{ mt: 8, textAlign: 'center' }}>
      <CircularProgress size={48} sx={{ mb: 2 }} />
      <Typography variant="h6">Completing authentication...</Typography>
      <Typography variant="body2" color="text.secondary">
        Redirecting to your workspace
      </Typography>
    </Container>
  );
};

export default OAuthCallback;
