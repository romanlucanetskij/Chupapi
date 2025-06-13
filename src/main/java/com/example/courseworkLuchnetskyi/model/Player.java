package com.example.courseworkLuchnetskyi.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "players")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Player {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private LocalDate birthDate;

    private String position;

    @ManyToOne
    private Team team;

    @OneToMany(mappedBy = "player")
    private List<Participation> participations;

    public int getMatchesPlayed() {
      return participations != null ? participations.size() : 0;
    }

    public int getGoalsScored() {
      return participations != null
        ? participations.stream().mapToInt(Participation::getGoals).sum()
        : 0;
    }

}
