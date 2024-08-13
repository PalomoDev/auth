// auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  Get, HttpException, HttpStatus, Logger
} from "@nestjs/common";
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './local-auth.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';
import { Roles } from './roles.decorator';
import { UserRole } from '../user/user.schema';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // Эндпоинт для входа пользователя
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  // Эндпоинт для регистрации нового пользователя
  @Post('register')
  async register(@Body() registerDto: { email: string; password: string }) {
    const logger = new Logger('AuthController');
    logger.log(`Attempt to register user with email: ${registerDto.email}`);

    try {
      const result = await this.authService.register(
        registerDto.email,
        registerDto.password,
      );

      logger.log(`User registered successfully: ${registerDto.email}`);

      return {
        user: {
          id: result.user.id,
          email: result.user.email,
          // Добавьте другие поля пользователя, которые вы хотите вернуть, исключая чувствительные данные
        },
        access_token: result.access_token
      };
    } catch (error) {
      logger.error(`Registration failed for email ${registerDto.email}: ${error.message}`);

      if (error.message === 'User already exists') {
        throw new HttpException('Пользователь с таким email уже существует', HttpStatus.CONFLICT);
      }

      throw new HttpException('Ошибка при регистрации', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  // Эндпоинт для запроса сброса пароля
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  // Эндпоинт для сброса пароля
  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: { token: string; newPassword: string },
  ) {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
    );
  }

  // Эндпоинт для повышения пользователя до роли админа (доступен только суперадмину)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.SUPER_ADMIN)
  @Post('promote-to-admin')
  async promoteToAdmin(@Body('userId') userId: string) {
    return this.authService.promoteToAdmin(userId);
  }
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    return this.authService.getProfile(req.user.userId);
  }
}
