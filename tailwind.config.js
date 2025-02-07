const remToPx = require('tailwindcss-rem-to-px');
export default {

  important: true,  // This
  content: [
    "./src/**/*.{html,js,ts,jsx,tsx}", "./src/*.{html,js,ts,jsx,tsx}", "./dist/*.{html, js}"],
  theme: {
    extend: {
      maxWidth: {
        '6xl': '1152px',
      },
      zIndex: {
        "max" : 2147483647
      }
    },
  },
  plugins: [remToPx()],
}

