/** @type {import('tailwindcss').Config} */
const remToPx = require('tailwindcss-rem-to-px');
export default {
  content: [
    "./src/**/*.{html,js,ts,jsx,tsx}", "./src/*.{html,js,ts,jsx,tsx}", "./dist/*.{html, js}"],
  theme: {
    extend: {},
  },
  plugins: [remToPx()],
}

