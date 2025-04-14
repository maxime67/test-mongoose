import mongoose from 'mongoose';

const {Schema} = mongoose;

// Schémas de base communs
const TimestampSchema = {
    type: String,
    match: [
        /^(((2000|2400|2800|(19|2[0-9](0[48]|[2468][048]|[13579][26])))-02-29)|(((19|2[0-9])[0-9]{2})-02-(0[1-9]|1[0-9]|2[0-8]))|(((19|2[0-9])[0-9]{2})-(0[13578]|10|12)-(0[1-9]|[12][0-9]|3[01]))|(((19|2[0-9])[0-9]{2})-(0[469]|11)-(0[1-9]|[12][0-9]|30)))T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$/,
        'Format de date/heure invalide. Utilisez ISO 8601/RFC3339'
    ],
    default: new Date().toISOString() // Valeur par défaut: date actuelle
};

const UuidSchema = {
    type: String,
    match: [
        /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/,
        'Format UUID v4 invalide'
    ],
    default: '00000000-0000-4000-a000-000000000000' // UUID par défaut
};

const LanguageSchema = {
    type: String,
    match: [
        /^[A-Za-z]{2,4}([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$/,
        'Code de langue invalide. Utilisez BCP 47'
    ],
    default: 'en'
};

const UriSchema = {
    type: String,
    maxlength: 2048,
    default: 'https://example.com'
};

// Schéma pour les médias supportant les descriptions
const SupportingMediaSchema = new Schema({
    type: {
        type: String,
        required: true,
        maxlength: 256,
        default: 'text/plain'
    },
    base64: {
        type: Boolean,
        default: false
    },
    value: {
        type: String,
        required: true,
        maxlength: 16384,
        default: ''
    }
}, {_id: false});

// Schéma pour les descriptions
const DescriptionSchema = new Schema({
    lang: LanguageSchema,
    value: {
        type: String,
        required: true,
        maxlength: 4096,
        default: 'Description non disponible'
    },
    supportingMedia: {
        type: [SupportingMediaSchema],
        default: []
    }
}, {_id: false});

// Schéma pour les références
const ReferenceSchema = new Schema({
    url: UriSchema,
    name: {
        type: String,
        maxlength: 512,
        default: 'Référence'
    },
    tags: {
        type: [{
            type: String,
        }],
        default: ['not-applicable']
    }
}, {_id: false});

// Schéma pour les types de problèmes
const ProblemTypeDescriptionSchema = new Schema({
    lang: LanguageSchema,
    description: {
        type: String,
        required: true,
        maxlength: 4096,
        default: 'Description du problème non disponible'
    },
    cweId: {
        type: String,
        default: 'CWE-0'
    },
    type: {
        type: String,
        maxlength: 128,
        default: 'CWE'
    },
    references: {
        type: [ReferenceSchema],
        default: []
    }
}, {_id: false});

const ProblemTypeSchema = new Schema({
    descriptions: {
        type: [ProblemTypeDescriptionSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins une description de problème est requise'],
        default: [{ lang: 'en', description: 'Description du problème non disponible', type: 'CWE', cweId: 'CWE-0' }]
    }
}, {_id: false});

// Schéma pour les métriques CVSS
const CvssV31Schema = new Schema({
    version: {
        type: String,
        enum: ['3.1'],
        required: true,
        default: '3.1'
    },
    vectorString: {
        type: String,
        required: true,
        match: [
            /^CVSS:3[.]1\/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*?(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/,
            'Format de vecteur CVSS 3.1 invalide'
        ],
        default: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    },
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10,
        default: 0
    },
    baseSeverity: {
        type: String,
        required: true,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default: 'NONE'
    },
    // Paramètres de base avec valeurs par défaut
    attackVector: {
        type: String,
        enum: ['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL'],
        default: 'NETWORK'
    },
    attackComplexity: {
        type: String,
        enum: ['HIGH', 'LOW'],
        default: 'LOW'
    },
    privilegesRequired: {
        type: String,
        enum: ['HIGH', 'LOW', 'NONE'],
        default: 'NONE'
    },
    userInteraction: {
        type: String,
        enum: ['NONE', 'REQUIRED'],
        default: 'NONE'
    },
    scope: {
        type: String,
        enum: ['UNCHANGED', 'CHANGED'],
        default: 'UNCHANGED'
    },
    confidentialityImpact: {
        type: String,
        enum: ['NONE', 'LOW', 'HIGH'],
        default: 'NONE'
    },
    integrityImpact: {
        type: String,
        enum: ['NONE', 'LOW', 'HIGH'],
        default: 'NONE'
    },
    availabilityImpact: {
        type: String,
        enum: ['NONE', 'LOW', 'HIGH'],
        default: 'NONE'
    },
    // Métriques temporelles (optionnelles)
    exploitCodeMaturity: {
        type: String,
        enum: ['UNPROVEN', 'PROOF_OF_CONCEPT', 'FUNCTIONAL', 'HIGH', 'NOT_DEFINED'],
        default: 'NOT_DEFINED'
    },
    remediationLevel: {
        type: String,
        enum: ['OFFICIAL_FIX', 'TEMPORARY_FIX', 'WORKAROUND', 'UNAVAILABLE', 'NOT_DEFINED'],
        default: 'NOT_DEFINED'
    },
    reportConfidence: {
        type: String,
        enum: ['UNKNOWN', 'REASONABLE', 'CONFIRMED', 'NOT_DEFINED'],
        default: 'NOT_DEFINED'
    },
    temporalScore: {
        type: Number,
        min: 0,
        max: 10,
        default: 0
    },
    temporalSeverity: {
        type: String,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default: 'NONE'
    }
}, {_id: false});

// Schéma pour les autres versions de CVSS simplifié (pour éviter la duplication)
const CvssV20Schema = new Schema({
    version: {
        type: String,
        enum: ['2.0'],
        required: true,
        default: '2.0'
    },
    vectorString: {
        type: String,
        default: 'AV:N/AC:L/Au:N/C:N/I:N/A:N'
    },
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10,
        default: 0
    },
    // Autres propriétés CVSS 2.0...
}, {_id: false, strict: false});

const CvssV30Schema = new Schema({
    version: {
        type: String,
        enum: ['3.0'],
        required: true,
        default: '3.0'
    },
    vectorString: {
        type: String,
        default: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    },
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10,
        default: 0
    },
    baseSeverity: {
        type: String,
        required: true,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default: 'NONE'
    },
    // Autres propriétés CVSS 3.0...
}, {_id: false, strict: false});

const CvssV40Schema = new Schema({
    version: {
        type: String,
        enum: ['4.0'],
        required: true,
        default: '4.0'
    },
    vectorString: {
        type: String,
        default: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'
    },
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10,
        default: 0
    },
    baseSeverity: {
        type: String,
        required: true,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default: 'NONE'
    },
    // Autres propriétés CVSS 4.0...
}, {_id: false, strict: false});

// Métriques (peut contenir divers formats CVSS)
const MetricSchema = new Schema({
    format: {
        type: String,
        default: 'CVSS'
    },
    scenarios: {
        type: [{
            lang: LanguageSchema,
            value: {
                type: String,
                default: 'GENERAL',
                maxlength: 4096
            }
        }],
        default: [{ lang: 'en', value: 'GENERAL' }]
    },
    cvssV2_0: CvssV20Schema,
    cvssV3_0: CvssV30Schema,
    cvssV3_1: CvssV31Schema,
    cvssV4_0: CvssV40Schema,
    other: {
        type: {
            type: String,
            maxlength: 128,
            default: ''
        },
        content: {
            type: Schema.Types.Mixed,
            default: {}
        }
    }
}, {_id: false});

// Schéma pour les gammes de versions
const VersionRangeSchema = new Schema({
    version: {
        type: String,
        required: true,
        maxlength: 1024,
        default: 'n/a'
    },
    status: {
        type: String,
        required: true,
        enum: ['affected', 'unaffected', 'unknown'],
        default: 'unknown'
    },
    versionType: {
        type: String,
        maxlength: 128,
        default: 'custom'
    },
    lessThan: {
        type: String,
        maxlength: 1024,
        default: ''
    },
    lessThanOrEqual: {
        type: String,
        maxlength: 1024,
        default: ''
    },
    changes: {
        type: [{
            at: {
                type: String,
                required: true,
                maxlength: 1024,
                default: 'n/a'
            },
            status: {
                type: String,
                required: true,
                enum: ['affected', 'unaffected', 'unknown'],
                default: 'unknown'
            }
        }],
        default: []
    }
}, {_id: false});

// Schéma pour les produits affectés
const ProductSchema = new Schema({
    vendor: {
        type: String,
        maxlength: 512,
        default: 'Non spécifié'
    },
    product: {
        type: String,
        maxlength: 2048,
        default: 'Non spécifié'
    },
    collectionURL: UriSchema,
    packageName: {
        type: String,
        maxlength: 2048,
        default: ''
    },
    cpes: {
        type: [{
            type: String,
            maxlength: 2048
        }],
        default: []
    },
    modules: {
        type: [{
            type: String,
            maxlength: 4096
        }],
        default: []
    },
    programFiles: {
        type: [{
            type: String,
            maxlength: 1024
        }],
        default: []
    },
    programRoutines: {
        type: [{
            name: {
                type: String,
                required: true,
                maxlength: 4096,
                default: 'Unknown'
            }
        }],
        default: []
    },
    platforms: {
        type: [{
            type: String,
            maxlength: 1024
        }],
        default: []
    },
    repo: UriSchema,
    defaultStatus: {
        type: String,
        enum: ['affected', 'unaffected', 'unknown'],
        default: 'unknown'
    },
    versions: {
        type: [VersionRangeSchema],
        default: []
    }
}, {_id: false});

// Schéma pour les crédits
const CreditSchema = new Schema({
    lang: LanguageSchema,
    value: {
        type: String,
        required: true,
        maxlength: 4096,
        default: 'Anonyme'
    },
    user: UuidSchema,
    type: {
        type: String,
        enum: [
            'finder',
            'reporter',
            'analyst',
            'coordinator',
            'remediation developer',
            'remediation reviewer',
            'remediation verifier',
            'tool',
            'sponsor',
            'other'
        ],
        default: 'finder'
    }
}, {_id: false});

// Schéma pour les timelines
const TimelineSchema = new Schema({
    time: {
        type: TimestampSchema,
    },
    lang: {
        type: LanguageSchema,
    },
    value: {
        type: String,
        required: true,
        maxlength: 4096,
        default: 'Événement non spécifié'
    }
}, {_id: false});

// Schéma pour les métadonnées du fournisseur
const ProviderMetadataSchema = new Schema({
    orgId: {
        type: UuidSchema,
    },
    shortName: {
        type: String,
        minlength: 2,
        maxlength: 32,
        default: 'Unknown'
    },
    dateUpdated: TimestampSchema
}, {_id: false});

// Schéma pour le conteneur CNA
const CnaContainerSchema = new Schema({
    providerMetadata: {
        type: ProviderMetadataSchema,
        required: true,
        default: () => ({
            orgId: '00000000-0000-4000-a000-000000000000',
            shortName: 'Unknown',
            dateUpdated: new Date().toISOString()
        })
    },
    dateAssigned: TimestampSchema,
    datePublic: TimestampSchema,
    title: {
        type: String,
        maxlength: 256,
        default: 'CVE sans titre'
    },
    descriptions: {
        type: [DescriptionSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins une description est requise'],
        default: [{ lang: 'en', value: 'Description non disponible' }]
    },
    affected: {
        type: [ProductSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins un produit affecté est requis'],
        default: [{ vendor: 'Non spécifié', product: 'Non spécifié' }]
    },
    problemTypes: {
        type: [ProblemTypeSchema],
        default: []
    },
    references: {
        type: [ReferenceSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins une référence est requise'],
        default: [{ url: 'https://example.com', name: 'Référence par défaut' }]
    },
    impacts: {
        type: [{
            capecId: {
                type: String,
                match: [/^CAPEC-[1-9][0-9]{0,4}$/, 'Format CAPEC-ID invalide'],
                default: 'CAPEC-1'
            },
            descriptions: {
                type: [DescriptionSchema],
                default: []
            }
        }],
        default: []
    },
    metrics: {
        type: [MetricSchema],
        default: []
    },
    configurations: {
        type: [DescriptionSchema],
        default: []
    },
    workarounds: {
        type: [DescriptionSchema],
        default: []
    },
    solutions: {
        type: [DescriptionSchema],
        default: []
    },
    exploits: {
        type: [DescriptionSchema],
        default: []
    },
    timeline: {
        type: [TimelineSchema],
        default: []
    },
    credits: {
        type: [CreditSchema],
        default: []
    },
    source: {
        type: Schema.Types.Mixed,
        default: { discovery: 'UNKNOWN' }
    },
    tags: {
        type: [{
            type: String,
        }],
        default: []
    }
}, {_id: false, strict: false});

// Schéma pour les conteneurs ADP
const AdpContainerSchema = new Schema({
    providerMetadata: {
        type: ProviderMetadataSchema,
        required: true,
        default: () => ({
            orgId: '00000000-0000-4000-a000-000000000000',
            shortName: 'Unknown',
            dateUpdated: new Date().toISOString()
        })
    },
    datePublic: TimestampSchema,
    title: {
        type: String,
        maxlength: 256,
        default: ''
    },
    descriptions: {
        type: [DescriptionSchema],
        default: []
    },
    affected: {
        type: [ProductSchema],
        default: []
    },
    problemTypes: {
        type: [ProblemTypeSchema],
        default: []
    },
    references: {
        type: [ReferenceSchema],
        default: []
    },
    impacts: {
        type: [{
            capecId: {
                type: String,
                match: [/^CAPEC-[1-9][0-9]{0,4}$/, 'Format CAPEC-ID invalide'],
                default: 'CAPEC-1'
            },
            descriptions: {
                type: [DescriptionSchema],
                default: []
            }
        }],
        default: []
    },
    metrics: {
        type: [MetricSchema],
        default: []
    },
    configurations: {
        type: [DescriptionSchema],
        default: []
    },
    workarounds: {
        type: [DescriptionSchema],
        default: []
    },
    solutions: {
        type: [DescriptionSchema],
        default: []
    },
    exploits: {
        type: [DescriptionSchema],
        default: []
    },
    timeline: {
        type: [TimelineSchema],
        default: []
    },
    credits: {
        type: [CreditSchema],
        default: []
    },
    source: {
        type: Schema.Types.Mixed,
        default: {}
    },
    tags: {
        type: [{
            type: String,
            enum: ['disputed']
        }],
        default: []
    }
}, {_id: false, strict: false});

// Schéma pour les métadonnées CVE
const CveMetadataSchema = new Schema({
    cveId: {
        type: String,
        match: [/^CVE-[0-9]{4}-[0-9]{4,19}$/, 'Format CVE-ID invalide'],
        default: 'CVE-0000-0000'
    },
    assignerOrgId: {
        type: UuidSchema,
    },
    assignerShortName: {
        type: String,
        minlength: 2,
        maxlength: 32,
        default: 'Unknown'
    },
    requesterUserId: UuidSchema,
    dateReserved: TimestampSchema,
    datePublished: TimestampSchema,
    dateUpdated: TimestampSchema,
    state: {
        type: String,
        required: true,
        enum: ['PUBLISHED', 'REJECTED'],
        default: 'PUBLISHED'
    },
    serial: {
        type: Number,
        min: 1,
        default: 1
    }
}, {_id: false});

// Schéma pour les containers
const ContainersSchema = new Schema({
    cna: {
        type: CnaContainerSchema,
        required: true,
        default: () => ({
            providerMetadata: {
                orgId: '00000000-0000-4000-a000-000000000000',
                shortName: 'Unknown',
                dateUpdated: new Date().toISOString()
            },
            descriptions: [{ lang: 'en', value: 'Description non disponible' }],
            affected: [{ vendor: 'Non spécifié', product: 'Non spécifié' }],
            references: [{ url: 'https://example.com', name: 'Référence par défaut' }]
        })
    },
    adp: {
        type: [AdpContainerSchema],
        default: []
    }
}, {_id: false});

// Schéma principal pour CVE
const CveSchema = new Schema({
    dataType: {
        type: String,
        required: true,
        enum: ['CVE_RECORD'],
        default: 'CVE_RECORD'
    },
    dataVersion: {
        type: String,
        required: true,
        match: [/^5\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$/, 'Format de version invalide'],
        default: '5.1'
    },
    cveMetadata: {
        type: CveMetadataSchema,
        required: true,
        default: () => ({
            cveId: 'CVE-0000-0000',
            state: 'PUBLISHED',
            dateReserved: new Date().toISOString(),
            datePublished: new Date().toISOString(),
            dateUpdated: new Date().toISOString()
        })
    },
    containers: {
        type: ContainersSchema,
        required: true,
        default: () => ({})
    }
}, {
    timestamps: true,
    collection: 'cves'
});

// Méthodes pour faciliter l'utilisation
CveSchema.methods.getTitle = function () {
    if (this.containers && this.containers.cna && this.containers.cna.title) {
        return this.containers.cna.title;
    }
    return 'CVE sans titre';
};

CveSchema.methods.getDescription = function (lang = 'en') {
    if (this.containers && this.containers.cna && this.containers.cna.descriptions) {
        const desc = this.containers.cna.descriptions.find(d => d.lang === lang || d.lang.startsWith(lang));
        return desc ? desc.value : (this.containers.cna.descriptions.length > 0 ?
            this.containers.cna.descriptions[0].value : 'Description non disponible');
    }
    return 'Description non disponible';
};

CveSchema.methods.getAffectedProducts = function () {
    if (this.containers && this.containers.cna && this.containers.cna.affected) {
        return this.containers.cna.affected;
    }
    return [];
};

CveSchema.methods.getCvssScores = function () {
    const scores = [];
    if (this.containers && this.containers.cna && this.containers.cna.metrics) {
        this.containers.cna.metrics.forEach(metric => {
            if (metric.cvssV2_0) scores.push({version: '2.0', ...metric.cvssV2_0});
            if (metric.cvssV3_0) scores.push({version: '3.0', ...metric.cvssV3_0});
            if (metric.cvssV3_1) scores.push({version: '3.1', ...metric.cvssV3_1});
            if (metric.cvssV4_0) scores.push({version: '4.0', ...metric.cvssV4_0});
        });
    }
    return scores;
};

CveSchema.methods.getProblemTypes = function () {
    if (this.containers && this.containers.cna && this.containers.cna.problemTypes) {
        return this.containers.cna.problemTypes;
    }
    return [];
};

CveSchema.methods.getReferences = function () {
    if (this.containers && this.containers.cna && this.containers.cna.references) {
        return this.containers.cna.references;
    }
    return [];
};

CveSchema.methods.getHighestSeverity = function () {
    const scores = this.getCvssScores();
    if (scores.length === 0) return 'UNKNOWN';

    const severityPriority = {
        'CRITICAL': 5,
        'HIGH': 4,
        'MEDIUM': 3,
        'LOW': 2,
        'NONE': 1,
        'UNKNOWN': 0
    };

    let highestSeverity = 'UNKNOWN';
    let highestPriority = 0;

    scores.forEach(score => {
        const severity = score.baseSeverity || 'UNKNOWN';
        const priority = severityPriority[severity] || 0;

        if (priority > highestPriority) {
            highestSeverity = severity;
            highestPriority = priority;
        }
    });

    return highestSeverity;
};

// Méthode statique pour rechercher par ID CVE
CveSchema.statics.findByCveId = function(cveId) {
    return this.findOne({ 'cveMetadata.cveId': cveId });
};

// Méthode statique pour rechercher par terme
CveSchema.statics.search = function(term, limit = 20) {
    const regex = new RegExp(term, 'i');
    return this.find({
        $or: [
            { 'cveMetadata.cveId': regex },
            { 'containers.cna.title': regex },
            { 'containers.cna.descriptions.value': regex }
        ]
    }).limit(limit);
};

// Création du modèle
const Cve = mongoose.model('Cve', CveSchema);

export default Cve;