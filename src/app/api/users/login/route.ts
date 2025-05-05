import {connect} from "@/dbConfig/dbConfig";
import User from "@/models/userModel"
import { NextRequest, NextResponse } from "next/server";
import bcryptjs from "bcryptjs"
import jwt from "jsonwebtoken"



//everytime we have to connect to database
connect() 

export async function POST(request:NextRequest) {
    try {
        const reqBody = await request.json()
        const {email, password} = reqBody;
        console.log(reqBody);

        //check if the user exists
        const user = await User.findOne({email})
        if(!user){
            return NextResponse.json(
                {error: "user does not exist"},
                {status: 400}
            )
        }

        //check if password is correct
        const validPassword = await bcryptjs.compare(password, user.password)
        
        if(!validPassword){
            return NextResponse.json(
                {error: "invalid password"},
                {status: 500}
            )
        }

        //after validation we create a token (created by jsonwebToken)-->(encrypted token)
        //we send this tokens in users cookies

        //this cookies helps to verify the users\



        //create token data
        const tokenData= {
            id : user._id,
            username: user.username,
            email: user.email
        }
        //above is just the token data now we are going to create token and srnd it to user


        //create token
        const token = await jwt.sign(tokenData, process.env.TOKEN_SECRET!, {expiresIn: "1d"})


        //this response is NextResponse can access user cookies
        const response = NextResponse.json({
            message: "Login successful",
            success: true
        })
        response.cookies.set("token", token, {
            httpOnly: true,
            
        })

        return response;

    } catch (error : any) {
        return NextResponse.json(
            {error: error.message},
            {status: 500}
        )
    }
}