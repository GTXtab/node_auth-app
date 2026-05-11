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
  return User.findByPk(id);
}

async function updateName(userId, newName) {
  const user = await User.findByPk(userId);

  if (!user) {
    throw ApiError.badRequest('User is not found');
  }

  user.name = newName;
  await user.save();
  return user;
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

  return user;
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

  const hashPassword = await bcrypt.hash(newPassword, 3);
  user.password = hashPassword;
  await user.save();
  return user;
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

export const userService = {
  getAllActivated,
  normalize,
  findByEmail,
  register,
  getUserById,
  updateName,
  updateEmail,
  updatePassword,
};
