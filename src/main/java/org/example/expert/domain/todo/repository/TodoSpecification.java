package org.example.expert.domain.todo.repository;

import java.time.LocalDate;
import java.time.LocalDateTime;

import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.jpa.domain.Specification;

import jakarta.persistence.criteria.JoinType;

public class TodoSpecification {
	public static Specification<Todo> fetchUserJoin() {
		return (root, query, criteriaBuilder) -> {
			if (Long.class != query.getResultType()) {
				root.fetch("user", JoinType.INNER);
			}
			return criteriaBuilder.conjunction();
		};
	}

	public static Specification<Todo> hasWeather(String weather) {
		return (root, query, criteriaBuilder) -> {
			if (weather == null || weather.isEmpty()) {
				return criteriaBuilder.conjunction();
			}

			String pattern = "%" + weather + "%";
			return criteriaBuilder.like(criteriaBuilder.lower(root.get("weather")), pattern.toLowerCase());
		};
	}

	public static Specification<Todo> updatedDateAfter(LocalDate startDate) {
		return (root, query, criteriaBuilder) -> {
			if (startDate == null) {
				return criteriaBuilder.conjunction();
			}
			return criteriaBuilder.greaterThanOrEqualTo(root.get("modifiedAt"), startDate);
		};
	}

	public static Specification<Todo> updatedDateBefore(LocalDate endDate) {
		return (root, query, criteriaBuilder) -> {
			if (endDate == null) {
				return criteriaBuilder.conjunction();
			}
			return criteriaBuilder.lessThanOrEqualTo(root.get("modifiedAt"), endDate);
		};
	}
}
