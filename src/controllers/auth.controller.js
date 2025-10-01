import logger from '#config/logger.js';
import { signupSchema, signinSchema } from '#validations/auth.validation.js';
import { formatValidationError } from '#utils/format.js';
import { jwttoken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';
import { createUser, authenticateUser } from '#services/auth.service.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);

    if (!validationResult.success)
      return res.status(400).json({
        message: formatValidationError(validationResult.error),
      });

    const { name, email, password, role } = validationResult.data;

    const user = await createUser({ name, email, password, role });

    const token = jwttoken.sign({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User registered successfully: ${email}`);

    res.status(201).json({
      message: 'User registered successfully',
      details: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Signup error: ', error);

    if (error.message === 'User with this email already exists')
      return res.status(409).json({ message: 'Email already exists' });

    next(error);
  }
};

export const signin = async (req, res, next) => {
  try {
    const validationResult = signinSchema.safeParse(req.body);

    if (!validationResult.success)
      return res.status(400).json({
        message: formatValidationError(validationResult.error),
      });

    const { email, password } = validationResult.data;

    const user = await authenticateUser(email, password);

    const token = jwttoken.sign({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User signed in successfully: ${email}`);

    res.status(200).json({
      message: 'User signed in successfully',
      details: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Signin error: ', error);

    if (error.message === 'User not found')
      return res.status(404).json({ message: 'User not found' });

    if (error.message === 'Invalid password')
      return res.status(401).json({ message: 'Invalid credentials' });

    next(error);
  }
};

export const signout = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User signed out successfully');

    res.status(200).json({
      message: 'User signed out successfully',
    });
  } catch (error) {
    logger.error('Signout error: ', error);
    next(error);
  }
};
