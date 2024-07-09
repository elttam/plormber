import { PrismaClient } from "@prisma/client";
import * as crypto from "crypto";

const TOTAL_ARTICLES = 100

const prisma = new PrismaClient()

function genRandomArticles(totalArticles: number): any[] {
  const articles = [];
  for(let i=0; i<totalArticles; i++) {
    articles.push({
      "title": crypto.randomBytes(4).toString("hex"),
      "body": crypto.randomBytes(128).toString("hex"),
      "published": true,
      categories: {
        create: {
          name: "blog"
        }
      }
    });
  }
  return articles
}

async function main() {
  await prisma.department.createMany({
    data: [
      {
        name: "Sales"
      },
      {
        name: "Managers"
      },
      {
        name: "Admins"
      }
    ]
  })

  await prisma.user.createMany({
    data: [
      {
        name: 'karen',
        email: 'karen@example.com',
        password: 'super secret passphrase',
        resetToken: crypto.randomBytes(8).toString('hex'),
        isAdmin: false
      },
      {
        name: 'jeff-the-manager',
        email: 'jeff-the-manager@example.com',
        password: 'mah name is jeff1',
        resetToken: crypto.randomBytes(8).toString('hex'),
        isAdmin: false
      },
      {
        name: 'mike-the-admin',
        email: 'mike-the-admin@example.com',
        password: 'kentocky froid chocken',
        resetToken: crypto.randomBytes(8).toString('hex'),
        isAdmin: true
      },
      {
        name: 'root',
        email: 'root@example.com',
        password: 'password1 should be good enough',
        resetToken: crypto.randomBytes(8).toString('hex'),
        isAdmin: true
      }
    ],
    skipDuplicates: true
  })

  await prisma.user.update({
    where: {
      email: "karen@example.com"
    },
    data: {
      articles: {
        create: genRandomArticles(TOTAL_ARTICLES)
      },
      departments: {
        connect: [
          {
            id: 1
          }
        ]
      }
    }
  })

  await prisma.user.update({
    where: {
      email: "jeff-the-manager@example.com"
    },
    data: {
      articles: {
        create: [
          {
            "title": "Important Post",
            "body": "Don't publish yet, it is secret and I haven't finished it yet... Hello world",
            "published": false,
            categories: {
              connect: [
                {
                  id: 1
                }
              ]
            }
          }
        ]
      },
      departments: {
        connect: [
          {
            id: 1
          },
          {
            id: 2
          }
        ]
      }
    }
  })

  await prisma.user.update({
    where: {
      email: "mike-the-admin@example.com"
    },
    data: {
      departments: {
        connect: [
          {
            id: 2
          },
          {
            id: 3
          }
        ]
      }
    }
  })

  await prisma.user.update({
    where: {
      email: "root@example.com"
    },
    data: {
      departments: {
        connect: [
          {
            id: 3
          }
        ]
      }
    }
  })

  const allUsers = await prisma.user.findMany()
  console.log('All users: ')
  console.dir(allUsers, { depth: null })

  const allPosts = await prisma.article.findMany();
  console.log('All posts: ')
  console.dir(allPosts, { depth: null })
}

main()
  .catch((e) => console.error(e))
  .finally(async () => await prisma.$disconnect())