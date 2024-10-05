import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersRepository } from './users.repository';
import { GetUserDto } from './dto/get-user.dto';

@Injectable()
export class UsersService {
  constructor(private readonly usersRepository: UsersRepository) {}

  async create(createUserDto: CreateUserDto) {
    return this.usersRepository.create({
      ...createUserDto,
      password: await bcrypt.hash(createUserDto.password, 10),
      // password: createUserDto.password,
    });
  }

  async verifyUser(email: string, password: string) {
    // const user = await this.usersRepository.findOne({ email });
    const user = await this.usersRepository.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('User not found.');
    }
    const passwordIsValid = await bcrypt.compare(password, user.password);
    // const passwordIsValid = password === user.password;
    if (!passwordIsValid) {
      throw new UnauthorizedException('Credentials are not valid.');
    }
    return user;
  }

  async getUser(getUserDto: GetUserDto) {
    return this.usersRepository.findOne(getUserDto);
  }
}
