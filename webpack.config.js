const HtmlWebpack    = require('html-webpack-plugin');
const MiniCssExtract = require('mini-css-extract-plugin');
const CopyPlugin     = require('copy-webpack-plugin');
/** son las cuatro opciones mas comunes para la configuración del archivo webpack
*   --mode
    --module
    --optimization
    --plugins
 */

module.exports = {

    mode: 'development',   //-- este cambio afecta directamente a la minificación del archivo main.js

    output: {  //-- resetea la carpeta de distribucion que te crea el run build 
        clean: true
    },

    module: {
        rules: [
            {
                test: /\.html$/,    //-- va a barreer todos los archivos HTML que encuentre
                loader: 'html-loader', //-- esta libreria se va a encargar de mostrarlos 
                options: {
                    sources: false
                }
            },
            {
                test: /\.css$/,
                exclude: /styles.css$/,
                use: ['style-loader', 'css-loader'] //-- trabajan en conjunto para identificar las importaciones de .css como .js
            },
            {
                test: /styles.css$/,
                use: [ MiniCssExtract.loader, 'css-loader']
            },
            {
                test: /\.(jpg|png|jpe?g|gif)$/,
                loader: 'file-loader'
            },
            /* {
                test: /\.m?js$/,
                exclude: /node_modules/,
                use: {
                  loader: "babel-loader",
                  options: {
                    presets: ['@babel/preset-env']
                  }
                }
            } */
        ]
    },
    
    optimization: {},

    plugins: [    //-- aqui van las configuraciones de las instancias de los plugins a utilizar

        new HtmlWebpack({
            title: 'miApp Webpack',
            //filename: 'ejemplo.html'    -- por defecto pone index.html pero se puede modificar
            template: './src/index.html'  //-- cual es el archivo que va simular que tiene el contenido a cargar
        }),

        new MiniCssExtract({
            filename: '[name].css',
            ignoreOrder: false
        }),

        new CopyPlugin({   //-- plugin para copiar y mover recursos
            patterns: [
                { from: 'src/assets/', to: 'assets/'}
            ]
            
        })

    ],
}