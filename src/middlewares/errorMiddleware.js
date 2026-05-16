import { ApiError } from '../exceptions/api.error.js';

export const errorMiddleware = (err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof ApiError) {
    return res.status(err.status).json({
      message: err.message,
      errors: err.errors,
    });
  }

  console.error(err);
  return res.status(500).json({ message: 'Server error' });
};
