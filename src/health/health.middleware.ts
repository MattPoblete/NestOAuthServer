import { Request, Response, NextFunction } from 'express';

export function healthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (req.path === '/') {
    res.status(200).json({
      statusCode: 200,
      message: 'Server is healthy',
    });
  }
  next();
}
