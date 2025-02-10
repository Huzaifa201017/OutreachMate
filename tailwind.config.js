const remToPx = require('tailwindcss-rem-to-px');
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx,js,jsx}"],
  theme: {
    extend: { 
      maxWidth: {
        '6xl': '1152px',
      },
      zIndex: {
        "max" : 2147483647
      }},
  },
  plugins: [remToPx()],
}

