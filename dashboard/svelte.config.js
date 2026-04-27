import adapter from '@sveltejs/adapter-static';

export default {
  kit: {
    adapter: adapter({
      pages: 'build',
      assets: 'build',
      fallback: '404.html',
      precompress: false,
    }),
    paths: {
      base: process.env.NODE_ENV === 'production' ? '/devsecops' : '',
    },
    prerender: {
      handleHttpError: ({ path, referrer, message }) => {
        // Ignore missing favicon
        if (path.endsWith('/favicon.png')) return;
        throw new Error(message);
      },
    },
  },
};
