import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/user.entity';
import { Session } from './auth/entities/session.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.POSTGRES_HOST || 'localhost',
      port: parseInt(process.env.POSTGRES_PORT) || 5432,
      username: process.env.POSTGRES_USER || 'nudex_user',
      password: process.env.POSTGRES_PASSWORD || 'nudex_pass',
      database: process.env.POSTGRES_DB || 'nudex_users',
      entities: [User, Session],
      synchronize: true,
      logging: false,
    }),
    PassportModule,
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET || 'nudex-secret-key-2026',
      signOptions: { expiresIn: '24h' },
    }),
    AuthModule,
    UsersModule,
  ],
})
export class AppModule {}