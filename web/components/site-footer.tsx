export default function SiteFooter() {
	return (
		<footer className='border-t border-border bg-background/70 py-10 text-center text-xs text-muted-foreground'>
			<div className='mx-auto flex w-full max-w-6xl flex-col items-center gap-3 px-6'>
				<div className='text-sm font-semibold text-foreground'>
					Encrypted Social Space
				</div>
				<div className='max-w-lg'>
					Secure collaboration for requests, responses, and real-time messaging
					with encrypted data at every step.
				</div>
				<div className='flex flex-wrap justify-center gap-4 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground/80'>
					<span>Privacy</span>
					<span>Security</span>
					<span>Support</span>
				</div>
			</div>
		</footer>
	);
}
