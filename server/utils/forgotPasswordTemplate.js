const forgotPasswordTemplate = ({ name, otp }) => {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ccc; border-radius: 5px;">
            <h2 style="color: #333;">Hello ${name},</h2>
            <p style="color: #555;">We received a request to reset your password. Please use the following OTP to proceed:</p>
            <h3 style="color: #007BFF;">${otp}</h3>
            <p style="color: #555;">If you did not request this, please ignore this email.</p>
            <p style="color: #555;">Thank you!</p>
        </div>
    `;
}

export default forgotPasswordTemplate;