import { ApiError } from '../exceptions/api.error.js';
import { User } from '../models/user.js';
import { v4 as uuidv4 } from 'uuid';
import { emailService } from './email.service.js';
import bcrypt from 'bcrypt';

export async function getAllActivated() {
  return User.findAll({
    where: {
      activationToken: null,
    },
  });
}

function normalize(user) {
  if (!user) return null;
  return { id: user.id, email: user.email, name: user.name };
}

async function findByEmail(email) {
  return User.findOne({ where: { email } });
}

async function getUserById(id) {
  const user = await User.findByPk(id);
  return normalize(user);
}

async function updateName(userId, newName) {
  const user = await User.findByPk(userId);

  if (!user) {
    throw ApiError.badRequest('User is not found');
  }

  user.name = newName;
  await user.save();

  return normalize(user);
}

async function updateEmail(userId, newEmail, password) {
  const user = await User.findByPk(userId);
  if (!user) {
    throw ApiError.badRequest('User is not found');
  }

  const isPassEquals = await bcrypt.compare(password, user.password);
  if (!isPassEquals) {
    throw ApiError.badRequest('Невірний пароль');
  }

  const candidate = await User.findOne({ where: { email: newEmail } });
  if (candidate) {
    throw ApiError.badRequest(
      `Пошта ${newEmail} вже використовується іншим користувачем`,
    );
  }

  const oldEmail = user.email;

  user.email = newEmail;
  user.activationToken = uuidv4();
  await user.save();

  await emailService.sendEmailChangeNotification(oldEmail, newEmail);

  await emailService.sendActivationEmail(newEmail, user.activationToken);

  return normalize(user);
}

async function updatePassword(
  userId,
  oldPassword,
  newPassword,
  confirmPassword,
) {
  const user = await User.findByPk(userId);

  if (!user) {
    throw ApiError.badRequest('User is not found');
  }

  if (newPassword !== confirmPassword) {
    throw ApiError.badRequest('Новий пароль та підтвердження не співпадають');
  }

  const isPassEquals = await bcrypt.compare(oldPassword, user.password);
  if (!isPassEquals) {
    throw ApiError.badRequest('Невірний старий пароль');
  }

  const hashPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashPassword;
  await user.save();

  return normalize(user);
}

async function register(email, password, name) {
  const activationToken = uuidv4();

  const existUser = await findByEmail(email);

  if (existUser) {
    throw ApiError.badRequest('User already exist', {
      email: 'User already exist',
    });
  }

  await User.create({ email, password, name, activationToken });
  await emailService.sendActivationEmail(email, activationToken);
}

const activate = async (activationToken) => {
  const user = await User.findOne({ where: { activationToken } });

  if (!user) {
    throw ApiError.badRequest('Invalid activation token');
  }

  user.activationToken = null;
  await user.save();

  return user;
};

async function forgotPassword(email) {
  const user = await User.findOne({ where: { email } });

  if (!user) {
    throw ApiError.badRequest('Користувача з таким email не знайдено');
  }

  user.resetToken = uuidv4();
  await user.save();

  await emailService.sendResetPasswordEmail(email, user.resetToken);
}

async function resetPassword(resetToken, newPassword) {
  const user = await User.findOne({ where: { resetToken } });

  if (!user) {
    throw ApiError.badRequest('Недійсний токен або час його дії минув');
  }

  user.password = await bcrypt.hash(newPassword, 10);

  user.resetToken = null;
  await user.save();
}

export const userService = {
  getAllActivated,
  normalize,
  findByEmail,
  register,
  getUserById,
  updateName,
  updateEmail,
  updatePassword,
  activate,
  forgotPassword,
  resetPassword,
};
