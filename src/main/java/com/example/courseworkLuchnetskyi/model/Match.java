package com.example.courseworkLuchnetskyi.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;

@Entity
@Table(name = "matches")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Match {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Tournament tournament;

    @ManyToOne
    private Team teamA;

    @ManyToOne
    private Team teamB;

    private LocalDate date;

    private Integer scoreA;

    private Integer scoreB;
}
