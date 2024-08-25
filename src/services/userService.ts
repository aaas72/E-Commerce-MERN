import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"; 
import userModel from "../models/userModel"

interface registerParams{
    firstName: string
    lastName: string
    email: string
    password: string
}

export const register = async ({firstName, lastName, email, password}: registerParams) =>{
    const findUser = await userModel.findOne({email})
    if(findUser){
        return {data:"User already exists", statusCode: 400};
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new userModel({firstName, lastName, email, password: hashedPassword})
    await newUser.save()

    return {data: generateJWT(`${firstName} ${lastName} ${email}`), statusCode: 200};}

    
interface loginParams{
    email: string
    password: string
}

export const login = async ({email, password}: loginParams) =>{
    const findUser = await userModel.findOne({email})
    if(!findUser){
        return {data:"User not found", statusCode: 400};
    }
    const passwordMatch = await bcrypt.compare(password, findUser.password);
    if(passwordMatch){
        return {data: generateJWT(`${email}`), statusCode: 200};    }

    return {data:"Incorrect password", statusCode: 400};
}


const generateJWT = (data: string) => {
    return jwt.sign({data}, 'RPmXkguXCbbjF6MXsQJ7OZtdQOZPvHn4')
}