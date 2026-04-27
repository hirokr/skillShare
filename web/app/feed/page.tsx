import React from "react";
import {
	Card,
	CardHeader,
	CardTitle,
	CardDescription,
	CardContent,
	CardFooter,
} from "@/components/ui/card";

const mockPosts = [
	{
		id: 1,
		title: "Post Title 1",
		description: "This is the description for post 1.",
		avatar: "https://via.placeholder.com/50",
		comments: ["Great post!", "Thanks for sharing."],
	},
	{
		id: 2,
		title: "Post Title 2",
		description: "This is the description for post 2.",
		avatar: "https://via.placeholder.com/50",
		comments: ["Interesting read.", "Loved it!"],
	},
];

const FeedPage = () => {
	return (
		<div className='space-y-4'>
			{mockPosts.map((post) => (
				<Card key={post.id} className='w-full'>
					<CardHeader>
						<div className='flex items-center space-x-4'>
							<img
								src={post.avatar}
								alt='Avatar'
								className='w-10 h-10 rounded-full'
							/>
							<CardTitle>{post.title}</CardTitle>
						</div>
					</CardHeader>
					<CardContent>
						<CardDescription>{post.description}</CardDescription>
					</CardContent>
					<CardFooter>
						<div className='space-y-2'>
							{post.comments.map((comment, index) => (
								<div key={index} className='text-sm text-muted-foreground'>
									{comment}
								</div>
							))}
						</div>
					</CardFooter>
				</Card>
			))}
		</div>
	);
};

export default FeedPage;
