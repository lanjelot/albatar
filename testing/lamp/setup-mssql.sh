#!/bin/bash
#sleep 30s

/opt/mssql-tools/bin/sqlcmd -S mssql -U sa -P Password1 -d master <<'EOF'
USE [master]
GO

DROP DATABASE IF EXISTS [anime_db];
GO

CREATE DATABASE [anime_db];
GO

USE [anime_db]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[anime](
  [Id] [int] IDENTITY(1,1) NOT NULL,
  [Name] [varchar](50) NOT NULL,
 CONSTRAINT [PK_Anime] PRIMARY KEY CLUSTERED
(
  [Id] ASC
)) ON [PRIMARY]
GO

SET IDENTITY_INSERT [dbo].[Anime] ON
GO
INSERT [dbo].[Anime] ([Id], [Name]) VALUES (1, N'Cowboy Bebop')
GO
INSERT [dbo].[Anime] ([Id], [Name]) VALUES (2, N'Great Teacher Onizuka')
GO
INSERT [dbo].[Anime] ([Id], [Name]) VALUES (3, N'One Piece')
GO
INSERT [dbo].[Anime] ([Id], [Name]) VALUES (4, N'Hajime No Ippo')
GO
SET IDENTITY_INSERT [dbo].[Anime] OFF
GO

DROP LOGIN [anime_user]
GO

CREATE LOGIN [anime_user] WITH PASSWORD = 'Password1';
GO

DROP USER IF EXISTS [anime_user];
GO

CREATE USER [anime_user] FOR LOGIN [anime_user] WITH DEFAULT_SCHEMA=[dbo]
GO

GRANT ALL ON Anime TO [anime_user];
GO
EOF
