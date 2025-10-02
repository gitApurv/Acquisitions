import aj from '#config/arcjet.js';
import logger from '#config/logger.js';
import { slidingWindow } from '@arcjet/node';

export const securityMiddleware = async (req, res, next) => {
  try {
    const role = req.user?.role || 'guest';

    let limit;

    switch (role) {
      case 'admin':
        limit = 20;
        break;
      case 'user':
        limit = 10;
        break;
      case 'guest':
        limit = 5;
        break;
    }

    const client = aj.withRule(
      slidingWindow({
        mode: 'LIVE',
        interval: '1m',
        max: limit,
        name: `${role}-rate-limit`,
      })
    );

    const decision = await client.protect(req);

    if (decision.isDenied()) {
      if (decision.reason.isRateLimit()) {
        logger.warn('Rate limit exceeded', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: 'Too many requests. Please try again later.',
        });
      } else if (decision.reason.isBot()) {
        logger.warn('Bot request blocked', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: 'Automated requests are not allowed.',
        });
      } else if (decision.reason.isShield()) {
        logger.warn('Shield blocked request', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: 'Request blocked by security policy.',
        });
      }
    }

    next();
  } catch (error) {
    console.error('Arcjet middleware error:', error);
    res.status(500).json({
      errro: 'Internal server error',
      message: 'Something went wrong with security middleware.',
    });
  }
};

export default securityMiddleware;
