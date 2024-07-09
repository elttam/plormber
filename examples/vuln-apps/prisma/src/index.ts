import { PrismaClient } from '@prisma/client'
import express from 'express'

const prisma = new PrismaClient();
const app = express();

app.use(express.json());

app.get('/articles', async (req, res) => {
    try {
        const posts = await prisma.article.findMany({
            where: req.query.filter as any
        })
        res.json(posts);
    } catch (error) {
        res.json([]);
    }
});

app.post('/articles/verybad', async (req, res) => {
    try {
        const posts = await prisma.article.findMany(req.body.filter)
        res.json(posts);
    } catch (error) {
        res.json([]);
    }
});


app.post('/articles', async (req, res) => {
    try {
        const query = req.body.query;
        query.published = true;
        const posts = await prisma.article.findMany({ where: query })
        res.json(posts);
    } catch (error) {
        console.log(error)
        res.json([]);
    }
});


app.post('/articles/time-based', async (req, res) => {
    try {
        const query = req.body.query;
        query.published = true;
        // Simulate some query occurring without returning the result.
        await prisma.article.findMany({ where: query })
    } catch (error) {
    }
    res.json([]);
});

app.listen(9999, () =>
  console.log('REST API server ready on port 9999'),
);
