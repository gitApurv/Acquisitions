import express from 'express';
import { signup } from '#controllers/auth.controller.js';

const router = express.Router();

router.post('/sign-up', signup);

router.post('/sign-in', (req, res) => {
  res.status(200).send('Sign in');
});

router.post('/sign-out', (req, res) => {
  res.status(200).send('Sign out');
});

export default router;
