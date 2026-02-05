import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

import { User } from '../users/entities/user.entity';
import { Session } from './entities/session.entity';
import { RegisterDto, LoginDto, RefreshTokenDto } from './dto/auth.dto';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    @InjectRepository(Session)
    private sessionsRepository: Repository<Session>,
    private jwtService: JwtService,
    private usersService: UsersService,
  ) {}

  async register(registerDto: RegisterDto) {
    const { email, password, name, avatar } = registerDto;

    // Check if user exists
    const existingUser = await this.usersRepository.findOne({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = this.usersRepository.create({
      email,
      password: hashedPassword,
      name,
      avatar,
    });

    const savedUser = await this.usersRepository.save(user);

    // Generate tokens
    const tokens = await this.generateTokens(savedUser);

    // Save session
    await this.createSession(savedUser.id, tokens);

    return {
      user: this.sanitizeUser(savedUser),
      ...tokens,
    };
  }

  async login(loginDto: LoginDto, userAgent?: string, ipAddress?: string) {
    const { email, password } = loginDto;

    // Find user
    const user = await this.usersRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('User account is disabled');
    }

    // Update last login
    await this.usersRepository.update(user.id, {
      lastLoginAt: new Date(),
    });

    // Generate tokens
    const tokens = await this.generateTokens(user);

    // Save session
    await this.createSession(user.id, tokens, userAgent, ipAddress);

    return {
      user: this.sanitizeUser(user),
      ...tokens,
    };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto) {
    const { refreshToken } = refreshTokenDto;

    // Find session
    const session = await this.sessionsRepository.findOne({
      where: { refreshToken, isActive: true },
      relations: ['user'],
    });

    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if session expired
    if (new Date() > session.expiresAt) {
      await this.sessionsRepository.update(session.id, { isActive: false });
      throw new UnauthorizedException('Refresh token expired');
    }

    // Generate new tokens
    const tokens = await this.generateTokens(session.user);

    // Update session
    await this.sessionsRepository.update(session.id, {
      token: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    });

    return {
      user: this.sanitizeUser(session.user),
      ...tokens,
    };
  }

  async logout(token: string) {
    // Deactivate session
    await this.sessionsRepository.update(
      { token, isActive: true },
      { isActive: false },
    );

    return { message: 'Logged out successfully' };
  }

  private async generateTokens(user: User) {
    const payload = { sub: user.id, email: user.email, role: user.role };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = uuidv4();

    return {
      accessToken,
      refreshToken,
      expiresIn: 86400, // 24 hours
    };
  }

  private async createSession(
    userId: string,
    tokens: any,
    userAgent?: string,
    ipAddress?: string,
  ) {
    // Deactivate old sessions (limit to 5 active sessions per user)
    const activeSessions = await this.sessionsRepository.count({
      where: { userId, isActive: true },
    });

    if (activeSessions >= 5) {
      const oldestSession = await this.sessionsRepository.findOne({
        where: { userId, isActive: true },
        order: { createdAt: 'ASC' },
      });

      if (oldestSession) {
        await this.sessionsRepository.update(oldestSession.id, {
          isActive: false,
        });
      }
    }

    // Create new session
    const session = this.sessionsRepository.create({
      userId,
      token: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      userAgent,
      ipAddress,
    });

    await this.sessionsRepository.save(session);
  }

  private sanitizeUser(user: User) {
    const { password, ...sanitized } = user;
    return sanitized;
  }
}