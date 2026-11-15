import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import createAccessToken from "../libs/jwt.js";

export const register = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        })
        const userSaved = await newUser.save();
        const token = await createAccessToken({ id: userSaved._id });
        res.cookie("token", token);
        res.json({ "message": "Usuario registrado exitosamente" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Error al registrar el usuario: ", error: error.message });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const userFound = await User.findOne({ email });
        if (!userFound) return res.status(400).json({ message: "Email no encontrado" });

        const isMatch = await bcrypt.compare(password, userFound.password);
        if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" });

        const token = await createAccessToken({ id: userFound._id });
        res.cookie("token", token);
        res.json({ "message": "Sesion iniciada exitosamente" })

    } catch (error) {
        res.status(500).json({ message: "Error al iniciar sesion: ", error: error.message });
    }
};

export const logout = (req, res) => {
    res.clearCookie("token", "", { expires: new Date(0) });
    return res.status(200).json({ message: "Sesion finalizada exitosamente" });
};