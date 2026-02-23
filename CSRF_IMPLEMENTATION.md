# CSRF Protection Implementation

## Overview
This implementation provides CSRF (Cross-Site Request Forgery) protection for state-changing requests using the double-submit cookie pattern with httpOnly cookies.

## Implementation Details

### Double-Submit Cookie Pattern
The implementation uses the double-submit cookie approach:
1. Client requests a CSRF token via `GET /auth/csrf`
2. Server generates a secure token and sends it in two places:
   - As a JSON response: `{ "csrfToken": "..." }`
   - As an httpOnly cookie named `csrf-token`
3. For state-changing requests, client must include the token in the `X-CSRF-Token` header
4. Server validates that the header token matches the cookie token

### Security Features
- **httpOnly Cookies**: CSRF token stored in httpOnly cookies (not accessible to JavaScript)
- **Secure Flag**: Cookie marked as secure in production environment
- **SameSite Strict**: Cookie uses SameSite=strict policy
- **1-Hour Expiry**: Tokens expire after 1 hour
- **Cryptographically Secure**: Tokens generated using crypto.randomBytes

## API Endpoints

### GET /auth/csrf
Retrieves a CSRF token for state-changing requests.

**Response:**
```json
{
  "csrfToken": "a1b2c3d4e5f6789012345678901234567890abcdef"
}
```

**Cookie Set:**
- Name: `csrf-token`
- Value: Same as returned in JSON
- HttpOnly: true
- Secure: true (in production)
- SameSite: strict
- MaxAge: 3600000 (1 hour)

### Protected Endpoints
The following endpoints require CSRF token validation:
- `POST /auth/login`
- `POST /auth/register`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/wallets/link`
- And other state-changing endpoints

## Frontend Integration

### 1. Get CSRF Token
```javascript
// On app initialization or before first state-changing request
async function getCsrfToken() {
  const response = await fetch('/auth/csrf', {
    method: 'GET',
    credentials: 'include' // Important: includes cookies
  });
  
  const data = await response.json();
  // Store the token for later use
  localStorage.setItem('csrfToken', data.csrfToken);
  return data.csrfToken;
}
```

### 2. Make State-Changing Requests
```javascript
async function makeAuthenticatedRequest(url, method, data) {
  const csrfToken = localStorage.getItem('csrfToken');
  
  const response = await fetch(url, {
    method: method,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken // Include CSRF token in header
    },
    body: JSON.stringify(data),
    credentials: 'include' // Important: includes cookies
  });
  
  return response;
}

// Example usage
await makeAuthenticatedRequest('/auth/login', 'POST', {
  email: 'user@example.com',
  password: 'password123'
});
```

### 3. Handle Token Expiry
```javascript
async function refreshToken() {
  try {
    await getCsrfToken(); // Get new token
    // Retry the failed request
  } catch (error) {
    // Handle refresh failure
    console.error('Failed to refresh CSRF token:', error);
  }
}
```

## Error Handling

When CSRF validation fails, the server returns:
- **Status Code**: 403 Forbidden
- **Response**: `{"statusCode":403,"message":"CSRF token validation failed"}`

Frontend should handle this by:
1. Refreshing the CSRF token
2. Retrying the request with the new token
3. Redirecting to login if refresh fails

## Testing

### Valid Request Example
```bash
# 1. Get CSRF token
curl -c cookies.txt http://localhost:3000/auth/csrf

# 2. Use token in state-changing request
curl -b cookies.txt -H "X-CSRF-Token: YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  http://localhost:3000/auth/login
```

### Invalid Request Example (Missing Token)
```bash
# This will fail with 403
curl -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  http://localhost:3000/auth/login
```

## Security Considerations

### What's Protected
- All non-GET HTTP methods (POST, PUT, PATCH, DELETE)
- State-changing operations that modify user data
- Authentication and session management endpoints

### What's Not Protected
- GET requests (read-only operations)
- Public endpoints that don't modify user state

### Best Practices
1. Always use HTTPS in production
2. Store CSRF token securely on client side
3. Refresh token before expiry
4. Handle 403 responses appropriately
5. Include `credentials: 'include'` in all fetch requests

## Token Lifecycle

1. **Generation**: Token created on `/auth/csrf` request
2. **Storage**: 
   - Client: Local storage/session storage
   - Server: httpOnly cookie
3. **Usage**: Included in `X-CSRF-Token` header for protected requests
4. **Validation**: Server compares header token with cookie token
5. **Expiry**: Tokens expire after 1 hour
6. **Refresh**: Get new token via `/auth/csrf` endpoint