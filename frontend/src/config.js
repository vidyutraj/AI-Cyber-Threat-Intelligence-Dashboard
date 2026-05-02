// API base URL — empty string means "same origin" (works with the Vite proxy
// in dev and with a reverse proxy in production).  Set VITE_API_BASE in a
// .env file to point to a remote backend.
export const API_BASE = import.meta.env.VITE_API_BASE ?? ''
