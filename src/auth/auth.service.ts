import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    constructor(
        private prisma:PrismaService,
        private jwtService: JwtService,
        private configService: ConfigService
    ){}

    async signupLocal(dto: AuthDto){
        const hash = await this.hashData(dto.password);
        const newUser = await this.prisma.user.create({
            data:{
                email: dto.email,
                hash,
            },
        });

        const tokens = await this.getTokens(newUser.id, newUser.email);
        await this.updateRtHash(newUser.id, tokens.refresh_token);

        return tokens;
    }

    async signinLocal(dto:AuthDto){
        const user = await this.prisma.user.findUnique({
            where:{
                email: dto.email
            }
        });

        if(!user) throw new ForbiddenException("User not found!");

        const passwordMatches = await bcrypt.compare(dto.password,user.hash);
        if(!passwordMatches) throw new ForbiddenException("Access Denied!");

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;

    }

    async logout(userId: number){
        await this.prisma.user.updateMany({
            where:{
                id:userId,
                hashedRt:{
                    not:null,
                }
            },
            data:{
                hashedRt:null
            }
        });
    }

    async refreshTokens(userId: number, rt: string){
        const user = await this.prisma.user.findUnique({
            where:{
                id:userId,
            }
        });

        if(!user || !user.hashedRt) throw new ForbiddenException("Access Denied!");

        const rtMatches = await bcrypt.compare(rt, user.hashedRt) ;
        if(!rtMatches) throw new ForbiddenException("Access Denied!");

    }
    

    // Utility functions

    hashData(data:string){
        return bcrypt.hash(data,10);
    }

    async getTokens(usersId: number, email:string){
        const [at,rt] = await Promise.all([
            this.jwtService.signAsync({
                sub: usersId,
                email,
            },{
                secret:this.configService.getOrThrow<string>('AT_SECRET'),
                expiresIn: 60 * 15,
            }),
            this.jwtService.signAsync({
                sub: usersId,
                email,
            },{
                secret:this.configService.getOrThrow<string>("RT_SECRET"),
                expiresIn: 60 * 60 * 24 * 7,
            })
        ]);
        return {
            access_token: at,
            refresh_token: rt
        }
    }

    async updateRtHash(userId: number, rt: string){
        const hash = await this.hashData(rt);
        await this.prisma.user.update({
            where:{
                id:userId
            },
            data:{
                hashedRt: hash,
            }
        });
    }

    
}
