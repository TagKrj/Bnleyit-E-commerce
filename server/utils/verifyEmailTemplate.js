const verifyEmailTEmplate = (name, url) => {
    return `
     <p> Dear ${name}</p>
    <p>Thank you for registering with Binkeyit</p>
    <a href="${url}"
    style="color: #fff; background-color: #007bff;margin-top: 10px, padding: 20px">
    Verify Email
    </a>
    `
}

export default verifyEmailTEmplate;