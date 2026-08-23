const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js',
    publicPath: '/',
  },
  module: {
    rules: [
      {
        test: /\.jsx?$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', { targets: 'defaults' }],
              '@babel/preset-react',
            ],
          },
        },
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader'],
      },
    ],
  },
  resolve: {
    extensions: ['.js', '.jsx'],
  },
  plugins: [
    // Bake the API base URL into the bundle; browsers have no process.env.
    new webpack.DefinePlugin({
      'process.env.REACT_APP_API_URL': JSON.stringify(
        process.env.REACT_APP_API_URL || 'http://localhost:8000'
      ),
    }),
  ],
  devServer: {
    static: {
      directory: path.join(__dirname, 'public'),
    },
    port: 3000,
    historyApiFallback: true,
    proxy: {
      '/auth': 'http://localhost:8000',
      '/profiles': 'http://localhost:8000',
      '/scan': 'http://localhost:8000',
      '/audit': 'http://localhost:8000',
    },
  },
};