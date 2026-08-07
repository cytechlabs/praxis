# API Proxy Setup Guide

This guide explains how to properly set up API endpoint proxying from the Next.js frontend to the FastAPI backend.

## Architecture Overview

The setup consists of three layers:
1. Frontend Service Layer (e.g., `systemService.ts`)
2. Next.js API Route (proxy layer)
3. FastAPI Backend

## Setting Up a New API Endpoint

### 1. Frontend Service Layer

Create a service function in an appropriate service file (e.g., `services/myService.ts`):

```typescript
// For GET requests
export const fetchData = async (accessToken: string) => {
  const response = await fetch(`/api/my-endpoint?accessToken=${encodeURIComponent(accessToken)}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to fetch data');
  }
  return response.json();
};

// For POST requests
export const createData = async (data: any, accessToken: string) => {
  const response = await fetch('/api/my-endpoint', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ...data,
      accessToken,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to create data');
  }
  return response.json();
};
```

### 2. Next.js API Route

Create a new file in `pages/api/` directory:

```typescript
// For GET requests (e.g., pages/api/my-endpoint.ts)
import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { accessToken } = req.query;

    if (!accessToken) {
      return res.status(401).json({ error: 'No access token provided' });
    }

    const response = await fetch('http://backend:8000/your/backend/endpoint', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    return res.status(200).json(data);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Failed to fetch data' });
  }
}

// For POST requests
import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { accessToken, ...data } = req.body;

    if (!accessToken) {
      return res.status(401).json({ error: 'No access token provided' });
    }

    const response = await fetch('http://backend:8000/your/backend/endpoint', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify(data),
    });

    const responseData = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(responseData);
    }

    return res.status(200).json(responseData);
  } catch (error) {
    console.error('Error creating data:', error);
    return res.status(500).json({ error: 'Failed to create data' });
  }
}
```

## Key Points

1. **Token Handling**:
   - For GET requests: Pass token as a query parameter from service layer
   - For POST requests: Include token in request body from service layer
   - API route extracts token and adds it to Authorization header for backend request

2. **URL Structure**:
   - Frontend service calls local Next.js API route: `/api/my-endpoint`
   - Next.js API route calls backend: `http://backend:8000/your/backend/endpoint`
   - Use `backend:8000` instead of `localhost:8000` for backend URL

3. **Error Handling**:
   - Service layer throws errors with meaningful messages
   - API route returns appropriate status codes and error messages
   - Console.error in API route for server-side logging

4. **HTTP Methods**:
   - Check request method and return 405 if not allowed
   - Use appropriate HTTP status codes for responses

## Example Usage in Components

```typescript
import { fetchData } from '../services/myService';

const MyComponent = () => {
  const { data: session } = useSession();

  const handleFetch = async () => {
    try {
      const data = await fetchData(session?.accessToken);
      // Handle success
    } catch (error) {
      // Handle error
    }
  };

  return (
    // Your component JSX
  );
};
```

## Common Issues

1. **400 Bad Request**:
   - Ensure accessToken is being passed correctly
   - Check that API route is forwarding token in Authorization header
   - Verify request body structure matches backend expectations

2. **CORS Issues**:
   - Not typically a problem as Next.js API routes act as a proxy
   - No need for CORS configuration on frontend

3. **Authentication Errors**:
   - Verify token is being extracted correctly from query/body
   - Ensure Authorization header is properly formatted: `Bearer <token>`

## Best Practices

1. Use TypeScript interfaces for request/response data
2. Implement consistent error handling across all endpoints
3. Use meaningful error messages
4. Log errors on the server side
5. Keep service functions focused and reusable
