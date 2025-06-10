import UserModel from "../models/user.model.js";
import jwt from "jsonwebtoken";


const generatedRefeshToken = async (userId) => {
    const token = await jwt.sign({ id: userId }, process.env.SECRET_KEY_REFRESH_TOKEN, { expiresIn: '7d' });

    const updateRefeshTokenUser = await UserModel.updateOne({ _id: userId },
        {
            refreshToken: token
        })

    return token;
}

export default generatedRefeshToken;