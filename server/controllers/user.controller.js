import sendEmail from '../config/sendEmail.js';
import UserModel from '../models/user.model.js';
import bcryptjs from 'bcryptjs';
import verifyEmailTEmplate from '../utils/verifyEmailTemplate.js';
import generateAccessToken from '../utils/generatedAccessToken.js';
import generateRefreshToken from '../utils/generatedRefeshToken.js';
import uploadImageCloudinary from '../utils/uploadimageCloudinary.js';
import generatedOtp from '../utils/generatedOtp.js';
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js';

export async function registerUserControllor(request, response) {
    try {
        const { name, email, password } = request.body;

        if (!name || !email || !password) {
            return response.status(400).json({
                message: "provide email, name and password",
                error: true,
                success: false
            });
        }

        const user = await UserModel.findOne({ email })
        if (user) {
            return response.json({
                message: "Already register email",
                error: true,
                success: false
            });
        }

        const salt = await bcryptjs.genSalt(10);
        const hashPassword = await bcryptjs.hash(password, salt);

        const payload = {
            name,
            email,
            password: hashPassword
        };
        const newUser = await UserModel(payload);
        const save = await newUser.save();
        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`;


        const vetifyemail = await sendEmail({
            sendTo: email,
            subject: "Verify email from Binkeyit",
            html: verifyEmailTEmplate({
                name,
                url: VerifyEmailUrl
            })
        });

        return response.json({
            message: "User registered successfully",
            error: false,
            success: true,
            data: save
        });
    }
    catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }

}

export async function verifyEmailController(request, response) {
    try {
        const { code } = request.body;
        const user = await UserModel.findOne({ _id: code });
        if (!user) {
            return response.status(400).json({
                message: "Invalid code",
                error: true,
                success: false
            });
        }

        const updatedUser = await UserModel.updateOne({ _id: code }, {
            verify_email: true
        });
        return response.json(
            {
                message: "verified successfully",
                success: true,
                error: false,
            })
    }
    catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: true
        })
    }
}

//login user

export async function loginController(request, response) {
    try {
        const { email, password } = request.body;

        if (!email || !password) {
            return response.status(400).json({
                message: "provide email and password",
                error: true,
                success: false
            });
        }

        const user = await UserModel.findOne({ email });
        if (!user) {
            return response.status(400).json({
                message: "User not register",
                error: true,
                success: false
            });
        }

        if (user.status !== "Active") {
            return response.status(400).json({
                message: "Contact to Admin",
                error: true,
                success: false
            });
        }

        const checkPassword = await bcryptjs.compare(password, user.password);
        if (!checkPassword) {
            return response.status(400).json({
                message: "Check your password",
                error: true,
                success: false
            });
        }

        const accesstoken = await generateAccessToken(user._id);
        const refreshToken = await generateRefreshToken(user._id);

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "None",
        };
        response.cookie("accessToken", accesstoken, cookieOptions)
        response.cookie("refreshToken", refreshToken, cookieOptions)

        return response.json({
            message: "Login successfully",
            error: false,
            success: true,
            data: {
                accesstoken,
                refreshToken,
            }
        })
    }
    catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//logout controller
export async function logoutController(request, response) {
    try {
        const userid = request.userId
        const cookieOption = {
            httpOnly: true,
            secure: true,
            sameSite: "None",
        }
        response.clearCookie("accessToken", cookieOption)
        response.clearCookie("refreshToken", cookieOption)

        const removeRefreshToken = await UserModel.findByIdAndUpdate(userid, {
            refreshToken: ""
        })

        return response.json({
            message: "Logout successfully",
            error: false,
            success: true
        });
    }
    catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//uploadd user avatar
export async function uploadAvatar(request, response) {
    try {
        const userId = request.userId;
        const image = request.file;
        const upload = await uploadImageCloudinary(image);

        const updatedUser = await UserModel.findByIdAndUpdate(userId, {
            avatar: upload.url
        })
        return response.json({
            message: "upload profile",
            data: {
                _id: userId,
                avatar: upload.url
            }
        });
    }
    catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//update user details
export async function updatedUserDetails(request, response) {
    try {
        const userId = request.userId;
        const { name, email, mobile, password } = request.body;
        let hashPassword = "";
        if (password) {
            const salt = await bcryptjs.genSalt(10);
            hashPassword = await bcryptjs.hash(password, salt);
        }
        const updatedUser = await UserModel.updateOne({ _id: userId }, {
            ...(name && { name: name }),
            ...(email && { email: email }),
            ...(mobile && { mobile: mobile }),
            ...(password && { password: hashPassword })
        })
        return response.json({
            message: "User details updated successfully",
            error: false,
            success: true,
            data: updatedUser
        });
    }
    catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//forgot password not login
export async function forgotPasswordControlller(request, response) {
    try {
        const { email } = request.body;
        const user = await UserModel.findOne({ email });
        if (!user) {
            return response.status(400).json({
                message: "Email not available",
                error: true,
                success: false
            });
        }

        const otp = generatedOtp();
        const expireTime = Date.now() + 60 * 60 * 1000;

        const update = await UserModel.findByIdAndUpdate(user._id, {
            forgot_password_otp: otp,
            forgot_password_expiry: new Date(expireTime).toISOString()
        })

        await sendEmail({
            sendTo: email,
            subject: "Forgot Password OTP",
            html: forgotPasswordTemplate({
                name: user.name,
                otp: otp
            })
        });

        return response.json({
            message: "Check your email for OTP",
            error: false,
            success: true,
            data: {
                otp,
                forgot_password_expiry: new Date(expireTime).toISOString()
            }
        });

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//verify forgot password otp
export async function verifyForgotPasswordOtp(request, response) {
    try {
        const { email, otp } = request.body;

        if (!email || !otp) {
            return response.status(400).json({
                message: "Provide email and otp",
                error: true,
                success: false
            });
        }

        const user = await UserModel.findOne({ email });

        if (!user) {
            return response.status(400).json({
                message: "Email not available",
                error: true,
                success: false
            });
        }

        const currentTime = new Date().toISOString();
        if (user.forgot_password_expiry < currentTime) {
            return response.status(400).json({
                message: "OTP expired, please request a new OTP",
                error: true,
                success: false
            });
        }

        if (otp !== user.forgot_password_otp) {
            return response.status(400).json({
                message: "Invalid OTP",
                error: true,
                success: false
            })
        }

        // OTP is valid, proceed with password reset

        return response.json({
            message: "successfully verified otp",
            error: false,
            success: true,

        });

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//reset password
export async function resetpassword(request, response) {
    try {
        const { email, newPassword, confirmPassword } = request.body;
        if (!email || !newPassword || !confirmPassword) {
            return response.status(400).json({
                message: "Provide email, new password and confirm password",
            });
        }

        const user = await UserModel.findOne({ email });
        if (!user) {
            return response.status(400).json({
                message: "Email not available",
                error: true,
                success: false
            });
        }

        if (newPassword !== confirmPassword) {
            return response.status(400).json({
                message: "New password and confirm password do not match",
                error: true,
                success: false
            });
        }

        const salt = await bcryptjs.genSalt(10);
        const hashPassword = await bcryptjs.hash(newPassword, salt);

        const update = await UserModel.findOneAndUpdate(user._id, {
            password: hashPassword,
        })

        return response.json({
            message: "Password reset successfully",
            error: false,
            success: true,
        })

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });

    }
}