import { Router } from 'express';
import { forgotPasswordControlller, loginController, logoutController, registerUserControllor, updatedUserDetails, uploadAvatar, verifyEmailController, verifyForgotPasswordOtp } from '../controllers/user.controller.js';
import auth from '../middleware/auth.js';
import upload from '../middleware/multer.js';

const userRouter = Router();

userRouter.post('/register', registerUserControllor)
userRouter.post('/verify-email', verifyEmailController);
userRouter.post('/login', loginController);
userRouter.get('/logout', auth, logoutController);
userRouter.put('/upload-avatar', auth, upload.single('avatar'), uploadAvatar);
userRouter.put('/update-user', auth, updatedUserDetails);
userRouter.put('/forgot-password', forgotPasswordControlller)
userRouter.put('/verify-forgot-password-otp', verifyForgotPasswordOtp);

export default userRouter;