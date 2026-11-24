import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import createAccessToken from "../libs/jwt.js";

export const register = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const usernameFound = await User.findOne({ username });
        if (usernameFound) return res.status(400).json({ message: "Este usuario ya existe" });

        const emailFound = await User.findOne({ email });
        if (emailFound) return res.status(400).json({ message: "Este correo ya existe " });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        })
        const userSaved = await newUser.save();
        const token = await createAccessToken({ id: userSaved._id });
        res.cookie("token", token);
        res.status(200).json({ "message": "Usuario registrado exitosamente" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Error al registrar el usuario: ", error: error.message });
    }
};

export const login = async (req, res) => {
    const { username, password } = req.body;
    try {
        const userFound = await User.findOne({ username });
        if (!userFound) return res.status(400).json({ message: "Usuario no encontrado" });

        const isMatch = await bcrypt.compare(password, userFound.password);
        if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" });

        const token = await createAccessToken({ id: userFound._id });
        res.cookie("token", token);
        res.status(200).json({ "message": "Sesion iniciada exitosamente" })

    } catch (error) {
        res.status(500).json({ message: "Error al iniciar sesion: ", error: error.message });
    }
};

export const logout = (req, res) => {
    res.clearCookie("token", "", { expires: new Date(0) });
    return res.status(200).json({ message: "Sesion finalizada exitosamente" });
};

export const profile = async (req, res) => {
    const userFound = await User.findById(req.user.id)
    if (!userFound) return res.status(400).json({ message: 'Usuario no encontrado' });
}