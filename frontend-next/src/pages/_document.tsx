import { Html, Head, Main, NextScript } from 'next/document';

// PRA-268: official Praxis favicons/app icons + explicit default theme.
// `data-theme="dark"` makes dark the 1.0 default runtime theme (the token system
// in globals.css switches to light under data-theme="light").
export default function Document() {
  return (
    <Html lang="en" data-theme="dark">
      <Head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png" />
        <link rel="apple-touch-icon" href="/brand/praxis-app-512.png" />
        <link rel="manifest" href="/manifest.webmanifest" />
        <meta name="theme-color" content="#0d0d0f" />
        <meta name="application-name" content="Praxis" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
