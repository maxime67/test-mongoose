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

// Méthodes utilitaires
ProductSchema.statics.findOrCreate = async function(productData) {
    // Chercher le produit par vendor et product
    let product = await this.findOne({
        vendor: productData.vendor,
        product: productData.product
    });

    if (!product) {
        // Si le produit n'existe pas, le créer
        product = new this(productData);
        console.log(product)
        await product.save();
    } else {
        // Si le produit existe, mettre à jour ses propriétés

        // Mise à jour des champs simples s'ils sont fournis et non vides
        if (productData.collectionURL) product.collectionURL = productData.collectionURL;
        if (productData.packageName) product.packageName = productData.packageName;
        if (productData.repo) product.repo = productData.repo;
        if (productData.defaultStatus) product.defaultStatus = productData.defaultStatus;

        // Mise à jour des tableaux (ajout des éléments uniques seulement)
        if (productData.cpes && productData.cpes.length) {
            productData.cpes.forEach(cpe => {
                if (!product.cpes.includes(cpe)) {
                    product.cpes.push(cpe);
                }
            });
        }

        if (productData.modules && productData.modules.length) {
            productData.modules.forEach(module => {
                if (!product.modules.includes(module)) {
                    product.modules.push(module);
                }
            });
        }

        if (productData.programFiles && productData.programFiles.length) {
            productData.programFiles.forEach(file => {
                if (!product.programFiles.includes(file)) {
                    product.programFiles.push(file);
                }
            });
        }

        if (productData.platforms && productData.platforms.length) {
            productData.platforms.forEach(platform => {
                if (!product.platforms.includes(platform)) {
                    product.platforms.push(platform);
                }
            });
        }

        // Gestion des versions (plus complexe car c'est un sous-document)
        if (productData.versions && productData.versions.length) {
            productData.versions.forEach(newVersion => {
                // Chercher si cette version existe déjà
                const existingVersionIndex = product.versions.findIndex(v =>
                    v.version === newVersion.version);

                if (existingVersionIndex === -1) {
                    // Si la version n'existe pas, l'ajouter
                    product.versions.push(newVersion);
                } else {
                    // Si la version existe, mettre à jour ses propriétés
                    const existingVersion = product.versions[existingVersionIndex];

                    if (newVersion.status) existingVersion.status = newVersion.status;
                    if (newVersion.versionType) existingVersion.versionType = newVersion.versionType;
                    if (newVersion.lessThan) existingVersion.lessThan = newVersion.lessThan;
                    if (newVersion.lessThanOrEqual) existingVersion.lessThanOrEqual = newVersion.lessThanOrEqual;

                    // Mise à jour des changements
                    if (newVersion.changes && newVersion.changes.length) {
                        newVersion.changes.forEach(newChange => {
                            const existingChangeIndex = existingVersion.changes.findIndex(c =>
                                c.at === newChange.at);

                            if (existingChangeIndex === -1) {
                                existingVersion.changes.push(newChange);
                            } else {
                                existingVersion.changes[existingChangeIndex].status = newChange.status;
                            }
                        });
                    }

                    // Mettre à jour la version dans le tableau
                    product.versions[existingVersionIndex] = existingVersion;
                }
            });
        }

        // Mise à jour des routines de programme
        if (productData.programRoutines && productData.programRoutines.length) {
            productData.programRoutines.forEach(newRoutine => {
                const existingRoutineIndex = product.programRoutines.findIndex(r =>
                    r.name === newRoutine.name);

                if (existingRoutineIndex === -1) {
                    product.programRoutines.push(newRoutine);
                }
                // Si la routine existe déjà, on ne fait rien
            });
        }

        // Sauvegarder les modifications
        await product.save();
    }

    return product;
};

// Méthode pour ajouter une référence à un CVE
ProductSchema.methods.addCveReference = async function(cveId) {
    if (!this.cves.includes(cveId)) {
        this.cves.push(cveId);
        await this.save();
    }
    return this;
};

const Product = mongoose.model('Product', ProductSchema);

export default Product;