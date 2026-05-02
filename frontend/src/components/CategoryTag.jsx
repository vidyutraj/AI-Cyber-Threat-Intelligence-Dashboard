function CategoryTag({ name }) {
  if (!name || !String(name).trim()) return null
  return <span className="category-tag">{name}</span>
}

function CategoryTags({ categories }) {
  if (!categories || !String(categories).trim()) return null
  const items = String(categories)
    .split(/\s*\/\s*|,\s*/)
    .map((s) => s.trim())
    .filter(Boolean)
  if (items.length === 0) return null
  return (
    <div className="category-tags">
      {items.map((cat, i) => (
        <CategoryTag key={`${cat}-${i}`} name={cat} />
      ))}
    </div>
  )
}

export { CategoryTag, CategoryTags }
