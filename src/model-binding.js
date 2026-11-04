export class ModelBindingError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

export function bindModel(pathname, { pattern, parameter, parse, find }) {
    const match = pattern.exec(pathname);
    if (!match) return null;

    const value = parse(match.groups[parameter]);
    if (value === null) throw new ModelBindingError(400, 'Identifiant de ressource invalide.');

    const model = find(value);
    if (!model) throw new ModelBindingError(404, 'Ressource introuvable.');

    return model;
}
