import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RecoveryCode } from '../entities/recovery-code.entity';
import { User } from '../entities/user.entity';
import { EncryptionService } from 'src/crypto/encryption.service';
import { UsersService } from './users.service';

@Module({
  imports: [TypeOrmModule.forFeature([User, RecoveryCode])],
  providers: [UsersService, EncryptionService],
  exports: [UsersService, EncryptionService],
})
export class UsersModule {}
