const mongoose = require('mongoose');

const connectDB = async () => {
    try {

        await mongoose.connect("mongodb://localhost:27017/");
        console.log('Connexion à MongoDB établie');
    } catch (error) {
        console.error('Erreur de connexion à MongoDB:', error.message);
        process.exit(1);
    }
};

module.exports = connectDB;