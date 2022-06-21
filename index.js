import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import {validationResult} from 'express-validator';
import {registerValidation} from './validations/auth.js';
import UserModel from './models/User.js'
import checkAuth from './utils/checkAuth.js'
import bcrypt from 'bcrypt'

mongoose.connect('mongodb+srv://MikaBona:25802586ua@cluster0.5uvyk.mongodb.net/blog?retryWrites=true&w=majority')
.then(() => console.log('DB ok'))
.catch((err) => console.log('DB error', err))

const app = express();

app.use(express.json())

app.post('/auth/login', async (req, res) => {
    try {
        const user = await UserModel.findOne({email: req.body.email})
        if (!user) {
            return res.status(404).json({
                message: 'Пользовательл не найден'
            })
        }

        const isValid = await bcrypt.compare(req.body.password, user._doc.passwordHash)

        if (!isValid) {
            return res.status(400).json({
                message: 'Неверный логин или пароль'
            })
        }

        const token = jwt.sign({
            _id: user._id
        }, 'secret123', {
            expiresIn: '30d'
        })

        const {passwordHash, ...userData} = user._doc

        res.json({
            ...userData,
            token
        })

    } catch (error) {
        res.status(500).json({
            message: 'Не удалось авторизоваться'
        })
    }
})

app.post('/auth/register', registerValidation, async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json(errors.array())
        }

        // Создание пользователя
        const password = req.body.password
        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(password, salt)

        const doc = new UserModel({
            email: req.body.email,
            fullName: req.body.fullName,
            passwordHash: hash,
            avatarUrl: req.body.avatarUrl,
        })

        //Создание пользователя в MongoDB
        const user = await doc.save();

        // Создаем Токен
        const token = jwt.sign({
            _id: user._id
        }, 'secret123', {
            expiresIn: '30d'
        })

        const {passwordHash, ...userData} = user._doc

        res.json({
            ...userData,
            token
        })
        } catch (error) {
            console.log(error)
        res.status(500).json({
            message: 'Не удалось зарегистрироваться'
        })
    }
});

app.get('/auth/me', checkAuth, async (req, res) => {
    try {
        const user = await UserModel.findById(req.userId)
        if (!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            })
        }
        const {passwordHash, ...userData} = user._doc

        res.json(userData)
    } catch (error) {
        console.log(error)
        res.status(500).json({
            message: 'Нет доступа'
        })
    }
})

app.listen(4444, (err) => {
    if (err) {
        return console.log(err);
    }

    console.log('Server Ok');
})
















