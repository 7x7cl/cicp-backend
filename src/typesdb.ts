export type UsuarioDB = {
    _id: string;
    modalidad: string;
    curso: string;
    letra: string;
    nombre: string;
    apellido: string;
    correos: string[];
    alumnos: string[];
    permisos: any[];
    tipo: string
};