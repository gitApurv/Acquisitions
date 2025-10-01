import bcrypt from 'bcrypt';
import logger from '#config/logger.js';
import { db } from '#config/database.js';
import { eq } from 'drizzle-orm';
import { users } from '#models/user.model.js';

export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (error) {
    logger.error(`Error while hashing password: ${error}`);
    throw new Error('Error while hashing password');
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    logger.error(`Error while comparing password: ${error}`);
    throw new Error('Error while comparing password');
  }
};

export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0)
      throw new Error('User with this email already exists');

    const hashedPassword = await hashPassword(password, 10);

    const [newUser] = await db
      .insert(users)
      .values({
        name,
        email,
        password: hashedPassword,
        role,
      })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      });

    logger.info(`User created successfully: ${newUser.email}`);

    return newUser;
  } catch (error) {
    logger.error(`Error while creating user: ${error}`);
    throw new Error('Error while creating user');
  }
};

export const authenticateUser = async (email, password) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!existingUser) throw new Error('User not found');

    const isPasswordValid = await comparePassword(
      password,
      existingUser.password
    );

    if (!isPasswordValid) throw new Error('Invalid password');

    logger.info(`User authenticated successfully: ${email}`);

    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      createdAt: existingUser.createdAt,
      updatedAt: existingUser.updatedAt,
    };
  } catch (error) {
    logger.error(`Error while authenticating user: ${error}`);
    throw error;
  }
};
