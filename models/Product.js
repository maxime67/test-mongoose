import mongoose from 'mongoose';

const {Schema} = mongoose;

// Réutilisation des schémas définis dans Cve.js
const UriSchema = {
    type: String,
    match: [
        /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i,
        'URI invalide'
    ],
    maxlength: 2048
};

// Schéma pour les gammes de versions
const VersionRangeSchema = new Schema({
    version: {
        type: String,
        required: true,
        maxlength: 1024
    },
    status: {
        type: String,
        required: true,
        enum: ['affected', 'unaffected', 'unknown']
    },
    versionType: {
        type: String,
        maxlength: 128
    },
    lessThan: {
        type: String,
        maxlength: 1024
    },
    lessThanOrEqual: {
        type: String,
        maxlength: 1024
    },
    changes: [{
        at: {
            type: String,
            required: true,
            maxlength: 1024
        },
        status: {
            type: String,
            required: true,
            enum: ['affected', 'unaffected', 'unknown']
        }
    }]
}, {_id: false});

// Schéma pour les routines de programme
const ProgramRoutineSchema = new Schema({
    name: {
        type: String,
        required: true,
        maxlength: 4096
    }
}, {_id: false});

// Schéma principal pour Product
const ProductSchema = new Schema({
    vendor: {
        type: String,
        required: true,
        maxlength: 512,
        index: true
    },
    product: {
        type: String,
        required: true,
        maxlength: 2048,
        index: true
    },
    collectionURL: UriSchema,
    packageName: {
        type: String,
        maxlength: 2048
    },
    cpes: [{
        type: String,
        maxlength: 2048
    }],
    modules: [{
        type: String,
        maxlength: 4096
    }],
    programFiles: [{
        type: String,
        maxlength: 1024
    }],
    programRoutines: [ProgramRoutineSchema],
    platforms: [{
        type: String,
        maxlength: 1024
    }],
    repo: UriSchema,
    defaultStatus: {
        type: String,
        enum: ['affected', 'unaffected', 'unknown'],
        default: 'unknown'
    },
    versions: [VersionRangeSchema],
    // Référence aux CVEs associés à ce produit
    cves: [{
        type: Schema.Types.ObjectId,
        ref: 'Cve'
    }]
}, {
    timestamps: true,
    collection: 'products'
});

// Index composé sur vendor et product pour recherche rapide
ProductSchema.index({ vendor: 1, product: 1 }, { unique: true });

// Méthodes utilitaires - Version corrigée pour éviter les erreurs de version
ProductSchema.statics.findOrCreate = async function(productData) {
    try {
        // Utiliser findOneAndUpdate avec upsert: true pour une opération atomique
        // Ce qui évite les problèmes de version de document
        const query = {
            vendor: productData.vendor,
            product: productData.product
        };

        // Construire l'objet de mise à jour
        const updateObj = {};

        // Ajout des champs simples s'ils sont fournis
        if (productData.collectionURL) updateObj.collectionURL = productData.collectionURL;
        if (productData.packageName) updateObj.packageName = productData.packageName;
        if (productData.repo) updateObj.repo = productData.repo;
        if (productData.defaultStatus) updateObj.defaultStatus = productData.defaultStatus;

        // Pour un nouvel enregistrement, définir les champs obligatoires
        const setObj = {
            ...updateObj,
            vendor: productData.vendor,
            product: productData.product
        };

        // Paramètres pour l'opération d'upsert
        const options = {
            new: true,           // Retourne le document mis à jour plutôt que l'original
            upsert: true,        // Crée le document s'il n'existe pas
            runValidators: true  // Exécute les validateurs du schéma
        };

        // Effectuer l'opération findOneAndUpdate avec upsert
        let product = await this.findOneAndUpdate(query, { $set: setObj }, options);

        // Mise à jour des tableaux si le produit existe
        if (product) {
            const arrayUpdates = {};

            // Préparer les mises à jour de type $addToSet pour les tableaux
            if (productData.cpes && productData.cpes.length) {
                arrayUpdates.$addToSet = arrayUpdates.$addToSet || {};
                arrayUpdates.$addToSet.cpes = { $each: productData.cpes };
            }

            if (productData.modules && productData.modules.length) {
                arrayUpdates.$addToSet = arrayUpdates.$addToSet || {};
                arrayUpdates.$addToSet.modules = { $each: productData.modules };
            }

            if (productData.programFiles && productData.programFiles.length) {
                arrayUpdates.$addToSet = arrayUpdates.$addToSet || {};
                arrayUpdates.$addToSet.programFiles = { $each: productData.programFiles };
            }

            if (productData.platforms && productData.platforms.length) {
                arrayUpdates.$addToSet = arrayUpdates.$addToSet || {};
                arrayUpdates.$addToSet.platforms = { $each: productData.platforms };
            }

            if (productData.programRoutines && productData.programRoutines.length) {
                arrayUpdates.$addToSet = arrayUpdates.$addToSet || {};
                arrayUpdates.$addToSet.programRoutines = { $each: productData.programRoutines };
            }

            // Effectuer les mises à jour des tableaux si nécessaire
            if (Object.keys(arrayUpdates).length > 0) {
                product = await this.findByIdAndUpdate(product._id, arrayUpdates, { new: true });
            }

            // Gestion des versions (plus complexe car c'est un sous-document)
            if (productData.versions && productData.versions.length) {
                // Pour chaque version fournie
                for (const newVersion of productData.versions) {
                    // Vérifier si cette version existe déjà
                    const existingVersion = product.versions.find(v => v.version === newVersion.version);

                    if (!existingVersion) {
                        // Si la version n'existe pas, l'ajouter avec une opération atomique
                        await this.findByIdAndUpdate(
                            product._id,
                            { $push: { versions: newVersion } },
                            { new: true }
                        );
                    } else {
                        // Si la version existe, préparer une mise à jour complexe
                        const versionUpdate = {};

                        // Mettre à jour les champs de la version existante
                        if (newVersion.status) versionUpdate[`versions.$.status`] = newVersion.status;
                        if (newVersion.versionType) versionUpdate[`versions.$.versionType`] = newVersion.versionType;
                        if (newVersion.lessThan) versionUpdate[`versions.$.lessThan`] = newVersion.lessThan;
                        if (newVersion.lessThanOrEqual) versionUpdate[`versions.$.lessThanOrEqual`] = newVersion.lessThanOrEqual;

                        // Mettre à jour la version si nécessaire
                        if (Object.keys(versionUpdate).length > 0) {
                            await this.findOneAndUpdate(
                                { _id: product._id, "versions.version": newVersion.version },
                                { $set: versionUpdate },
                                { new: true }
                            );
                        }

                        // Gestion des changements si présents
                        if (newVersion.changes && newVersion.changes.length) {
                            for (const newChange of newVersion.changes) {
                                // Vérifier si ce changement existe déjà
                                const existingChangeIndex = product.versions
                                    .find(v => v.version === newVersion.version)
                                    ?.changes.findIndex(c => c.at === newChange.at);

                                if (existingChangeIndex === -1 || existingChangeIndex === undefined) {
                                    // Si le changement n'existe pas, l'ajouter
                                    await this.findOneAndUpdate(
                                        { _id: product._id, "versions.version": newVersion.version },
                                        { $push: { "versions.$.changes": newChange } },
                                        { new: true }
                                    );
                                } else {
                                    // Si le changement existe, mettre à jour son statut
                                    // Cette opération est plus complexe et nécessite une mise à jour avec arrayFilters
                                    await this.findOneAndUpdate(
                                        { _id: product._id },
                                        {
                                            $set: {
                                                "versions.$[ver].changes.$[chg].status": newChange.status
                                            }
                                        },
                                        {
                                            arrayFilters: [
                                                { "ver.version": newVersion.version },
                                                { "chg.at": newChange.at }
                                            ],
                                            new: true
                                        }
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Récupérer le produit mis à jour final
            product = await this.findById(product._id);
        }

        return product;
    } catch (error) {
        console.error(`Erreur dans findOrCreate pour ${productData.vendor}/${productData.product}:`, error);
        throw error;
    }
};

// Méthode pour ajouter une référence à un CVE - Version corrigée utilisant une opération atomique
ProductSchema.methods.addCveReference = async function(cveId) {
    if (!this.cves.includes(cveId)) {
        // Utiliser findByIdAndUpdate avec $addToSet pour éviter les doublons et les problèmes de version
        return await this.constructor.findByIdAndUpdate(
            this._id,
            { $addToSet: { cves: cveId } },
            { new: true }
        );
    }
    return this;
};

const Product = mongoose.model('Product', ProductSchema);

export default Product;