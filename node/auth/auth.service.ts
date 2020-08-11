import { Injectable, UnauthorizedException, NotAcceptableException, Inject, forwardRef, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { SignOptions } from 'jsonwebtoken';
import { UsersService } from '../../shared/services';
import { User } from '../../modules/user';
import { LoginPayload } from '../../shared/dto/login.payload';

@Injectable()
export class AuthService {

    constructor(
        private readonly jwtService: JwtService,
        @Inject(forwardRef(() => UsersService)) private readonly usersService: UsersService,
    ) { }

    createToken(user: User, options: SignOptions = {}) {
        const payload = { email: user.email, id: user.id };
        return {    
            token: this.jwtService.sign(payload, options)
        };
    }

    async validateUser(payload: LoginPayload): Promise<any> {
        const verify = await this.usersService.getByEmailAndPass(payload.email, payload.password);
        if (!verify) {
            throw new UnauthorizedException('You have entered an invalid email or password.');
        }

        let user = await this.usersService.withRelations({
            email: verify.email
        }, ['dealers', 'groups']);

        return user;
    }  

    async refreshToken(request: any): Promise<any> {
        // invalid token - synchronous
        try {
            var decoded = this.jwtService.decode(request.token, { complete: true });
            let payload = decoded['payload'];

            if (payload) {
                delete payload.iat;
                delete payload.exp;
            }

            let token = this.jwtService.sign({ email: payload.email, id: payload.id });
            return {
                token : token
            }
        } catch(err) {
            throw new NotAcceptableException('provided token is invalid.');
        }
    }

    async logout(request: any) {
        let user = request.user;
        let timestamp = Date.now()/100;
        return true;
    }

    async adminLogin(payload: LoginPayload): Promise<any> {
        const verify = await this.usersService.adminLogin(payload.email, payload.password);
        if (!verify) {
            throw new UnauthorizedException('You have entered an invalid email or password.');
        }

        let user = await this.usersService.withRelations({
            email: verify.email
        });

        return user;
    }
    
    async adminForgotPassword(payload: any): Promise<any> {
        const verify = await this.usersService.adminForgotPassword(payload);
        
        if (!verify) {
            throw new NotFoundException('No user found with provided email address.');
        }
        
        await this.usersService.sendForgotPasswordMail(verify);

        let user = await this.usersService.withRelations({
            email: verify.email
        });

        return user;
    }

    async adminResetPassword(payload: any): Promise<any> {
        const user = await this.usersService.adminResetPassword(payload);

        if (!user) {
            throw new NotFoundException('No user found with provided email address.');
        }
        delete user.password;
        return user;
    }

    async verifyToken(payload: any): Promise<any> {
        const token = await this.usersService.verifyToken(payload);

        if (!token) {
            throw new NotAcceptableException('Token is expired or you cant\'t access this request.');
        }
     
        return token;
    }
}