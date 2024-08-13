// auth/auth.service.ts
import { ConflictException, Injectable, InternalServerErrorException, UnauthorizedException } from "@nestjs/common";
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { ConfigService } from '@nestjs/config';
import { User, UserRole } from '../user/user.schema';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // Проверка учетных данных пользователя
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.passwordHash))) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { passwordHash, ...result } = user.toObject();
      return result;
    }
    return null;
  }

  // Вход пользователя и генерация JWT токена
  async login(user: any) {
    console.log('Начало выполнения функции login'); // Логирование начала выполнения функции

    // Формирование payload для токена
    const payload = { email: user.email, sub: user._id, role: user.role };
    console.log('Сформирован payload для токена:', payload); // Логирование payload

    // Генерация токена
    const accessToken = this.jwtService.sign(payload);
    console.log('Токен успешно сгенерирован:', accessToken); // Логирование сгенерированного токена

    // Возврат объекта с токеном и информацией о пользователе
    const result = {
      access_token: accessToken,
      user: {
        _id: user._id,
        email: user.email,
        role: user.role,
        // добавьте любые другие свойства, которые вам могут понадобиться
      },
    };

    console.log('Возвращаемый объект:', result); // Логирование возвращаемого объекта
    return result;
  }

  async register(
    email: string,
    password: string,
  ): Promise<{ user: Partial<User>; access_token: string }> {
    try {
      const isSuperAdmin = email === process.env.SUPER_ADMIN_EMAIL;
      const role = isSuperAdmin ? UserRole.SUPER_ADMIN : UserRole.USER;
      const user = await this.userService.create(email, password, role);
      const access_token = this.jwtService.sign({
        sub: user.id,
        email: user.email,
      });

      // Возвращаем объект с информацией о пользователе и токеном
      return {
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          // Добавьте другие необходимые поля пользователя, исключая чувствительные данные
        },
        access_token,
      };
    } catch (error) {
      if (error.code === '23505') {
        // Код ошибки PostgreSQL для нарушения уникальности
        throw new ConflictException('User already exists');
      }
      throw new InternalServerErrorException('Error during registration');
    }
  }

  // Запрос на сброс пароля
  async forgotPassword(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    const resetToken = uuidv4();
    const resetExpires = new Date(Date.now() + 3600000); // 1 час от текущего времени
    await this.userService.setResetPasswordToken(
      user._id,
      resetToken,
      resetExpires,
    );
    // Здесь должна быть логика отправки email с токеном сброса пароля
    return { message: 'Reset password instructions sent to email' };
  }

  // Сброс пароля
  async resetPassword(token: string, newPassword: string) {
    const user = await this.userService.findByEmail(token);
    if (!user || !user.resetPasswordToken || user.resetPasswordExpires < new Date()) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }
    await this.userService.resetPassword(user._id, newPassword);
    return { message: 'Password reset successfully' };
  }

  // Повышение пользователя до роли админа
  async promoteToAdmin(userId: string) {
    await this.userService.promoteToAdmin(userId);
    return { message: 'User promoted to admin successfully' };
  }
  async getProfile(userId: string) {
    const user = await this.userService.findById(userId);
    if (user) {
      const { passwordHash, ...result } = user.toObject();
      return result;
    }
    return null;
  }
}
